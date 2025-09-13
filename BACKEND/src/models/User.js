const { getConnection } = require("../config/database");
const bcrypt = require("bcrypt");

/**
 * Clase que maneja operaciones relacionadas con los usuarios en la base de datos.
 */
class User {
    /**
     * Crea un nuevo usuario en la base de datos.
     * 
     * @param {Object} userData - Objeto que contiene la información del usuario
     * @returns {Promise<number>} Devuelve el ID del usuario que se creó.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async create(userData) {
        let connection;

        try {
            connection = await getConnection();

            const query = `
                INSERT INTO users (email, username, password_hash, first_name, last_name, role_id, verification_token) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `;

            const values = [
                userData.email,
                userData.username,
                userData.password_hash,
                userData.first_name,
                userData.last_name,
                userData.role_id,
                userData.verification_token,
            ];

            const [result] = await connection.execute(query, values);
            return result.insertId;
        } catch (error) {
            console.error("Error creando usuario:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * Busca un usuario por su email.
     * 
     * @param {string} email - Email del usuario que se quiere buscar
     * @returns {Promise<Object|undefined>} - Devuelve un objeto con los datos del usuario o 'undefined' si no hay resultados.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async findByEmail(email){
        let connection;
        try {
            connection = await getConnection();
            const query = `
                SELECT u.*, r.name as role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                WHERE u.email = ?
            `;
            const [rows] = await connection.execute(query, [email]);
            return rows[0];
        } catch (error) {
            console.error("Error buscando usuario por email:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * 
     * @param {number} - ID del usuario a buscar.
     * @returns {Promise<Object|undefined>} - Devuelve un objeto con los datos del usuario o 'undefined' si no hay resultados.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async findById(id){
        let connection;
        try {
            connection = await getConnection();
            const query = `
                SELECT u.*, r.name as role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                WHERE u.id = ?
            `;
            const [rows] = await connection.execute(query, [id]);
            return rows[0];
        } catch (error) {
            console.error("Error buscando usuario por id:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * 
     * @param {number} userId - ID del usuario a actualizar.
     * @param {number} attempts - Número de intentos fallidos actuales.
     * @param {Date|null} lockUntil - Fecha y hora hasta la que la cuenta permanecerá bloqueada, o `null` si no aplica.
     * @returns {Promise<boolean>} - Devuelve `true` si el usuario fue actualizado correctamente.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async updateLoginAttempts(userId, attempts, lockUntil = null) {
        let connection;
        try {
            connection = await getConnection();
            const query = `
                UPDATE users
                SET failed_login_attempts = ?, account_locked_until = ?
                WHERE id = ?
            `;
            const [result] = await connection.execute(query, [attempts, lockUntil, userId]);
            return result.affectedRows > 0;
        } catch (error) {
            console.error("Error actualizando intentos de login:", error);
            throw error;    
        } finally {
            if (connection) connection.release();
        }
    }
}

(async () => {
    const r = await User.updateLoginAttempts(1, 0);
    console.log("¿Se actualizó?:", r);
    process.exit();
})();
