const express = require("express");
const mongoose = require("mongoose");
const { handleErr } = require("./errorHandler.js");
const { asyncWrapper } = require("./asyncWrapper.js");
const dotenv = require("dotenv");
dotenv.config();
const userModel = require("./userModel.js");
const apiUserDataModel = require("./apiUserDataModel.js");
const { connectDB } = require("./connectDB.js");
const { getTypes } = require("./getTypes.js");
const { populatePokemons } = require("./populatePokemon.js");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const {
  AuthError,
  BadRequest,
  DbError,
  NotFoundError,
} = require("./errors.js");

const app = express();
app.use(express.json());
app.use(
  cors({
    exposedHeaders: ["auth-token-access", "auth-token-refresh"],
  })
);

let refreshTokens = [];
let pokeModel = null;
const parseToken = (req) => {
  if (req.header("Authorization")) {
    const [tokenType, token] = req.header("Authorization").split(" ");
    return { tokenType, token };
  } else {
    return { tokenType: null, token: null };
  }
};

app.post(
  "/register",
  asyncWrapper(async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
      throw new BadRequest(
        "Missing one or more of: username, password and/or email."
      );
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const userWithHashedPassword = {
      username,
      password: hashedPassword,
      email,
    };

    const user = await userModel.create(userWithHashedPassword);
    res.send(user);
  })
);

app.post(
  "/requestNewAccessToken",
  asyncWrapper(async (req, res) => {
    const { tokenType, token: refreshToken } = parseToken(req);
    if (tokenType !== "Refresh") {
      throw new AuthError("No Token: Please provide a token.");
    }
    if (!refreshTokens.includes(refreshToken)) {
      throw new AuthError("Invalid Token: Please provide a valid token.");
    }
    try {
      const payload = await jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      const accessToken = jwt.sign(
        { user: payload.user },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "11s" }
      );
      res.header("auth-token-access", "Bearer " + accessToken);
      res.send("All good!");
    } catch (error) {
      throw new AuthError("Invalid Token: Please provide a valid token.");
    }
  })
);

app.post(
  "/login",
  asyncWrapper(async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new BadRequest("Missing one or more of: username and/or password.");
    }
    const user = await userModel.findOne({ username });
    if (!user) throw new AuthError("User not found");

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) throw new AuthError("Password is incorrect");

    const accessToken = jwt.sign(
      { user: user },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "10s" }
    );
    const refreshToken = jwt.sign(
      { user: user },
      process.env.REFRESH_TOKEN_SECRET
    );
    refreshTokens.push(refreshToken);

    await userModel.updateOne({ username }, { token_invalid: false });

    res.header("auth-token-access", "Bearer " + accessToken);
    res.header("auth-token-refresh", "Refresh " + refreshToken);

    res.json(user);
  })
);

app.post(
  "/logout",
  asyncWrapper(async (req, res) => {
    const { tokenType, token } = parseToken(req);
    if (!token) {
      throw new AuthError(
        "No Token: Please provide the access token using the headers."
      );
    }
    if (tokenType !== "Bearer") {
      throw new AuthError(
        "Wrong Token Type: Please provide an access token using the headers."
      );
    }
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const { username } = payload.user;
    const user = await userModel.findOne({ username });
    if (!user) {
      throw new AuthError("User not found");
    }
    await userModel.updateOne({ username }, { token_invalid: true });

    refreshTokenUsers = refreshTokens.map(
      (token) =>
        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET).user.username
    );
    refreshTokenIndex = refreshTokenUsers.indexOf(username);
    if (refreshTokenIndex > -1) refreshTokens.splice(refreshTokenIndex, 1);
    res.send("Logged out");
  })
);

app.delete(
  "/user",
  asyncWrapper(async (req, res) => {
    const { username } = req.body;
    const user = await userModel.deleteOne({ username });
    res.send(user);
  })
);

const authUser = asyncWrapper(async (req, res, next) => {
  const { tokenType, token } = parseToken(req);
  if (!token) {
    throw new AuthError(
      "No Token: Please provide the access token using the headers."
    );
  }
  if (tokenType !== "Bearer") {
    throw new AuthError(
      "Wrong Token Type: Please provide an access token using the headers."
    );
  }
  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const { username } = payload.user;
    req.username = username;
    const user = await userModel.findOne({ username });
    if (user.token_invalid) {
      throw new AuthError("Invalid Token Verification. Log in again.");
    }
    // Create a new ApiUserData document
    await apiUserDataModel.create({
      userId: username,
      timestamp: new Date(),
      endpoint: req.originalUrl,
      status: res.statusCode,
    });
    next();
  } catch (err) {
    throw new AuthError("Invalid Token Verification. Log in again.");
  }
});

const authAdmin = asyncWrapper(async (req, res, next) => {
  const { tokenType, token } = parseToken(req);
  if (tokenType === "Bearer") {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    if (payload?.user?.role == "admin" && !payload?.user?.token_invalid) {
      return next();
    }
  }
  throw new AuthError("Access denied");
});

app.use(authUser);
app.get("/", (req, res) => {
  res.send("ok");
});

app.get(
  "/pokemons",
  asyncWrapper(async (req, res) => {
    const docs = await pokeModel.find({}).sort({ id: 1 });
    res.json(docs);
  })
);

app.use(authAdmin);
const timeWindow = 1 * 60 * 60 * 1000; // 1 hour in milliseconds
app.get("/uniqueApiUsers", async (req, res) => {
  try {
    const currentTime = new Date();
    const startTime = new Date(currentTime - timeWindow); // Calculate start time by subtracting time window from current time
    const uniqueApiUsersData = await apiUserDataModel.distinct("userId", {
      createdAt: { $gte: startTime, $lte: currentTime },
    }); // Filter by createdAt field within the time window
    res.json(uniqueApiUsersData);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch unique API users data" });
  }
});

app.get("/topApiUsers", async (req, res) => {
  try {
    // const currentTime = new Date();
    // const startTime = new Date(currentTime - timeWindow); // Calculate start time by subtracting time window from current time
    const topApiUsersData = await apiUserDataModel.aggregate([
      // { $match: { createdAt: { $gte: startTime, $lte: currentTime } } }, // Filter by createdAt field within the time window
      { $group: { _id: "$userId", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $project: { _id: 0, userId: "$_id", count: 1 } },
    ]);
    res.json(topApiUsersData);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch top API users data" });
  }
});

app.get("/topUsersByEndpoint", async (req, res) => {
  try {
    const topUsersByEndpointData = await apiUserDataModel.aggregate([
      {
        $group: {
          _id: { endpoint: "$endpoint", userId: "$userId" },
          count: { $sum: 1 },
        },
      },
      { $sort: { "_id.endpoint": 1, count: -1 } },
      {
        $group: {
          _id: "$_id.endpoint",
          endpoint: { $first: "$_id.endpoint" },
          topUser: { $first: "$_id.userId" },
          count: { $first: "$count" },
        },
      },
      { $project: { _id: 0, endpoint: 1, topUser: 1, count: 1 } },
    ]);
    res.json(topUsersByEndpointData);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to fetch top users by endpoint data" });
  }
});

// Route for fetching 4xx errors by endpoint
app.get("/errors4xxByEndpoint", async (req, res) => {
  try {
    const currentTime = new Date();
    const startTime = new Date(currentTime - timeWindow);

    const errors4xxByEndpointData = await apiUserDataModel
      .find({
        status: { $gte: 400, $lt: 500 },
        timestamp: { $gte: startTime, $lte: currentTime },
      })
      .limit(20);
    res.json(errors4xxByEndpointData);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to fetch 4xx errors by endpoint data" });
  }
});

// Route for fetching recent 4xx/5xx errors
app.get("/recentErrors4xx5xx", async (req, res) => {
  try {
    const currentTime = new Date();
    const startTime = new Date(currentTime - timeWindow);

    const recentErrors4xx5xxData = await apiUserDataModel
      .find({
        status: { $gte: 400, $lt: 600 },
        timestamp: { $gte: startTime, $lte: currentTime },
      })
      .limit(20);
    res.json(recentErrors4xx5xxData);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to fetch recent 4xx/5xx errors data" });
  }
});

app.get("*", function (req, res) {
  throw new BadRequest("Route does not exist.");
});

const start = asyncWrapper(async () => {
  await connectDB({ drop: false });
  const pokeSchema = await getTypes();
  // pokeModel = await populatePokemons(pokeSchema);
  pokeModel = mongoose.model("pokemons", pokeSchema);

  app.listen(process.env.SERVER_PORT, async (err) => {
    if (err) throw new DbError(err);
    else {
      console.log(`Server is running on port: ${process.env.SERVER_PORT}`);
      const adminUser = await userModel.findOne({ username: "admin" });
      if (!adminUser)
        userModel.create({
          username: "admin",
          password: bcrypt.hashSync("admin", 10),
          role: "admin",
          email: "admin@admin.ca",
        });
      const user = await userModel.findOne({ username: "user" });
      if (!user)
        userModel.create({
          username: "user",
          password: bcrypt.hashSync("user", 10),
          role: "user",
          email: "user@user.ca",
        });
    }
  });
});

app.use(handleErr);
start();
