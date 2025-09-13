require('dotenv').config({ path: './../../.env' });
const nodemailer = require('nodemailer');

const host  = process.env.EMAIL_HOST;

console.log("host: ", host);

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: false, // Usamos TLS (STARTTLS)
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false, // Solo en desarrollo: ignora errores de certificado TLS
  },
});

const enviarCorreo = async () => {
  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_TO_TEST,
      subject: 'Correo de prueba',
      text: '¡Hola! Este es un correo enviado desde Node.js con Gmail SMTP.',
    });

    console.log('Correo enviado con éxito:', info.response);
  } catch (error) {
    console.error('Error al enviar el correo:', error);
  }
};

enviarCorreo();
