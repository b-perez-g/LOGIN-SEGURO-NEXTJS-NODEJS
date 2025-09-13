const mysql = require('mysql2/promise');
require('dotenv').config({ path: './../../.env' });

// Crear pool de conexión
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

async function getConnection() {
    try {
        const connection = await pool.getConnection();
        return connection;
    } catch (error) {
        console.error('❌ Error al obtener conexión de la base de datos:', error);
        throw error;
    }
}

module.exports = {
    pool,
    getConnection
};
