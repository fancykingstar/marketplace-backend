const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const passport = require("passport");
const cors = require("cors");
const morgan = require("morgan");
const path = require("path");
require("dotenv").config();

const logger = require("./configs/logger");

const users = require("./routes/users");

// eslint-disable no-console

// Initial express app
const app = express();
// Initial http server
const server = require("http").Server(app);
// Initial web socket
// SetInterval
const getApiAndEmit = "TODO";

// Log requests info
app.use(morgan("dev"));

// Handle CORS
app.use(cors());

// Body parser middleware
app.use(bodyParser.json({ limit: "50mb" }));
app.use(
    bodyParser.urlencoded({
        limit: "50mb",
        extended: true,
    })
);

const debugMode = process.env.NODE_ENV === "development";
const relativePath = debugMode ? "../../" : "../..";

// Database config
const db = process.env.DEV_DB;

// Connect to MongoDB
mongoose
    .connect(db, { useNewUrlParser: true })
    .then(() => logger.info("MongoDB connected"))
    .catch((err) => logger.error(err));
mongoose.set("useCreateIndex", true);

// Passport Config
app.use(passport.initialize());
require("./configs/passport")(passport);

// Use routes
app.use("/api/users", users);
// Io init

if (!debugMode) {
    app.use(express.static(path.join(__dirname, relativePath, "build")));
}

app.use(require("./helpers/error-handler"));

app.get("/*", function (req, res) {
    if (req.xhr || req.headers.accept.indexOf("json") > -1) {
        // send your xhr response here
        res.sendStatus(404);
    } else {
        // send your normal response here
        res.sendFile(path.join(__dirname, relativePath, "build", "index.html"));
    }
});

const port = process.env.PORT || 5000;

server.listen(port, () => logger.info(`Server running on port ${port}`));

module.exports = app;
