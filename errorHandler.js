const apiUserDataModel = require("./apiUserDataModel.js");

handleErr = async (err, req, res, next) => {
  const username = req.username || null;

  await apiUserDataModel.create({
    userId: username,
    timestamp: new Date(),
    endpoint: req.originalUrl,
    status: err.code || 500,
  });

  if (!err.code) {
    console.log(err.message);
    res.status(500).json({ name: err.constructor.name, message: err.message });
  } else {
    console.log(err.message);
    res.status(err.code).json({ name: err.name, message: err.message });
  }
};

module.exports = { handleErr };
