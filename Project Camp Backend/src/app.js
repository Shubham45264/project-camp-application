import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

/* ===============================
   BASIC MIDDLEWARE
================================ */
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

/* ===============================
   CORS CONFIGURATION (FIXED)
================================ */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:8080",
  "https://project-camp-frontend.netlify.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (Postman, mobile apps)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

/* ===============================
   ROUTES
================================ */
import healthcheckrouter from "./routes/healthcheck.routes.js";
import authRouter from "./routes/auth.routes.js";
import projectRouter from "./routes/project.routes.js";
import taskRouter from "./routes/task.routes.js";
import noteRouter from "./routes/note.routes.js";

app.use("/api/v1/healthcheck", healthcheckrouter);
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/projects", projectRouter);
app.use("/api/v1/tasks", taskRouter);
app.use("/api/v1/notes", noteRouter);

/* ===============================
   ROOT ROUTE
================================ */
app.get("/", (req, res) => {
  res.send("Project Camp API is running 🚀");
});

/* ===============================
   ERROR HANDLER (LAST)
================================ */
import { errorHandler } from "./middlewares/error.middleware.js";
app.use(errorHandler);

export default app;
