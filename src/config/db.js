import mysql from "mysql2/promise";

export const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "security_incident_db",
  port: Number(process.env.DB_PORT || 3306),
  connectionLimit: 10,
  charset: "utf8mb4_general_ci",
});
