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

            const [result] = await connection.execute(
                `INSERT INTO users (email, username, password_hash, first_name, last_name, role_id, verification_token) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    userData.email,
                    userData.username,
                    userData.password_hash,
                    userData.first_name,
                    userData.last_name,
                    userData.role_id,
                    userData.verification_token,
                ]
            );

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
    static async findByEmail(email) {
        let connection;
        try {
            connection = await getConnection();

            const [rows] = await connection.execute(
                `SELECT u.*, r.name as role_name
                 FROM users u
                 LEFT JOIN roles r ON u.role_id = r.id
                 WHERE u.email = ?`,
                [email]
            );

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
    static async findById(id) {
        let connection;
        try {
            connection = await getConnection();

            const [rows] = await connection.execute(
                `SELECT u.*, r.name as role_name
                 FROM users u
                 LEFT JOIN roles r ON u.role_id = r.id
                 WHERE u.id = ?`,
                [id]
            );

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

            const [result] = await connection.execute(
                `UPDATE users
                 SET failed_login_attempts = ?, account_locked_until = ?
                 WHERE id = ?`,
                [attempts, lockUntil, userId]
            );

            return result.affectedRows > 0;
        } catch (error) {
            console.error("Error actualizando intentos de login:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * Actualiza el último inicio de sesión del usuario.
     *
     * @param {number} userId - ID del usuario a actualizar.
     * @returns {Promise<boolean>} - Devuelve `true` si el usuario fue actualizado correctamente.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async updateLastLogin(userId) {
        let connection;
        try {
            connection = await getConnection();

            const [result] = await connection.execute(
                `UPDATE users 
                 SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0 
                 WHERE id = ?`,
                [userId]
            );

            return result.affectedRows > 0;
        } catch (error) {
            console.error("Error actualizando last_login:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * Actualiza el token de restablecimiento de contraseña y su fecha de expiración.
     *
     * @param {*} email
     * @param {*} token
     * @param {*} expires
     * @returns {Promise<boolean>} - Devuelve `true` si el usuario fue actualizado correctamente.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async setResetToken(email, token, expires) {
        let connection;
        try {
            connection = await getConnection();

            const [result] = await connection.execute(
                `UPDATE users
                 SET reset_password_token = ?, reset_password_expires = ?
                 WHERE email = ?`,
                [token, expires, email]
            );

            return result.affectedRows > 0;
        } catch (error) {
            console.error("Error actualizando el reset token", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * Restablece la contraseña de un usuario usando un token de recuperación válido.
     * 
     * @param {string} token - Token de restablecimiento
     * @param {string} newPassword - Nueva contraseña
     * @returns {Promise<boolean>} - Devuelve `true` si el usuario fue actualizado correctamente.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async resetPassword(token, newPassword) {
        let connection;
        try {
            connection = await getConnection();

            const hashedPassword = await bcrypt.hash(
                newPassword,
                parseInt(process.env.BCRYPT_ROUNDS)
            );

            const [result] = await connection.execute(
                `UPDATE users 
                 SET password_hash = ?, reset_password_token = NULL, reset_password_expires = NULL 
                 WHERE reset_password_token = ? AND reset_password_expires > NOW()`,
                [hashedPassword, token]
            );

            return result.affectedRows > 0;

        }catch (error) {
            console.error("Error al resetear la contraseña:", error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    /**
     * Verifica la dirección de correo de un usuario mediante un token de verificación.
     * 
     * @param {string} token - Token de verificación enviado previamente al correo del usuario.
     * @returns {Promise<boolean>} - Devuelve `true` si el usuario fue actualizado correctamente.
     * @throws {Error} - Lanza un error si ocurre algún problema durante la consulta a la base de datos.
     */
    static async verifyEmail(token) {
        let connection;
        try {
            connection = await getConnection();

            const [result] = await connection.execute(
                `UPDATE users 
                 SET is_verified = true, verification_token = NULL 
                 WHERE verification_token = ?`,
                [token]
            );

            return result.affectedRows > 0;

        } catch (error) {
            console.error("Error actualizando verificacion de correo:", error);
            throw error;
        } finally {
            connection.release();
        }
    }
}
