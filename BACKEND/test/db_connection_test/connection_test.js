// testConnection.js
const { pool } = require('./../../src/config/database');

const testConnection = async () => {
    try {
        const connection = await pool.getConnection();
        console.log('Conexión establecida con la BD');
        connection.release();
        await pool.end();
    } catch (error) {
        console.error('Error al conectar con la BD', error);
        process.exit(1);
    }
};

testConnection();
