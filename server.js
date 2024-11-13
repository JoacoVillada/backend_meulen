const express = require("express");
const mysql = require("mysql2"); // Cambiado a mysql2
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const salt = 10;

const app = express();
const corsOptions = {
  origin: "http://localhost:3000", // Origen permitido
  credentials: true, // Permitir credenciales
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Crear la conexión con mysql2
const db = mysql.createConnection({
  host: "autorack.proxy.rlwy.net",
  user: "root",
  password: "OIDpojUTTBLmuJdjEfGAXELMVuLqnKBn",
  database: "railway",
  port: 54627,
});

// Conectar y manejar errores de autenticación
db.connect((error) => {
  if (error) {
    console.error("Error al conectar a la base de datos:", error);
  } else {
    console.log("Conectado a la base de datos");
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`listening on port ${PORT}`);
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token; //COKIEEE
  if (!token) {
    return res.json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ Error: "Token no correct" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get("/", verifyUser, (req, res) => {
  return res.json("Success");
});

app.post("/signup", (req, res) => {
  const sql = "INSERT INTO usuarios (`nombre`, `email`, `password`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hassing password" });
    const values = [req.body.name, req.body.email, hash];
    console.log("ayuda", values);
    db.query(sql, [values], (err, data) => {
      if (err) {
        return res.json("Error");
      }
      return res.json(data);
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM usuarios WHERE `email` = ?";

  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Login error in server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (response) {
            const name = data[0].name;
            const userId = data[0].id; // Obtener el ID del usuario
            const type = data[0].type;
            const token = jwt.sign({ name, userId }, "jwt-secret-key", {
              // Incluir userId en el token
              expiresIn: "1d",
            });
            //res.cookie("token", token); ///COOOKIEEEEE
            return res.json({ message: "Success", userId, type, token }); // Pasar el userId en la respuesta
          } else {
            return res.json({ message: "Failed" });
          }
        }
      );
    } else {
      return res.json({ message: "User not found" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token"); //COOOKIIEEESSS
  res.clearCookie("userId");
  return res.json("nashe");
});

// COSAS DEL USUARIO ---------------------

// Ruta para obtener los datos de la tabla productos
app.get("/productos", (req, res) => {
  const sql = "SELECT * FROM productos";

  db.query(sql, (err, data) => {
    if (err) {
      return res.json({ Error: "Error al obtener los productos" });
    }
    return res.json(data);
  });
});

// -- Confirmar Pedido

app.post("/crearPedido", (req, res) => {
  const { lista_productos, id_cliente, precio_total } = req.body;

  const sql =
    "INSERT INTO pedidos (`lista_productos`, `id_cliente`, `precio_total`) VALUES (?, ?, ?)";

  db.query(
    sql,
    [JSON.stringify(lista_productos), id_cliente, precio_total],
    (err, result) => {
      if (err) {
        return res.json({ Error: "Error al crear el pedido" });
      }
      return res.json({ Success: "Pedido creado exitosamente", data: result });
    }
  );
});

// VER PEDIDOSSS

// backend/index.js o rutas/pedidos.js
app.get("/verPedidos/:userId", (req, res) => {
  const userId = req.params.userId;
  const sql = "SELECT * FROM pedidos WHERE id_cliente = ?";

  db.query(sql, [userId], (err, data) => {
    //console.log("AAAAAAAA", data);
    if (err) {
      return res.status(500).json({ Error: "Error al obtener los pedidos" });
    }
    res.json(data);
  });
});

app.get("/editarUsuario/:id", (req, res) => {
  const sql = "SELECT * FROM usuarios where id = ?";
  const id = req.params.id;
  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Error: err });
    return res.json({ result });
  });
});

app.put("/update/:id", (req, res) => {
  const sql = "UPDATE usuarios SET `nombre` = ?, `email` = ? WHERE id = ?";
  const id = req.params.id;
  db.query(sql, [req.body.name, req.body.email, id], (err, result) => {
    if (err) return res.json("ERROR");
    return res.json({ updated: true });
  });
});

// RECUPERAR CONTRASEÑA ------------------

app.post("/forgotPass", (req, res) => {
  const { email } = req.body;
});

// ADMIN AUTH

// Endpoint para verificar si el usuario es admin
app.get("/auth/admin", (req, res) => {
  if (!req.session.userId) {
    return res.json({ message: "No autorizado" });
  }

  const sql = "SELECT type FROM usuarios WHERE id = ?";
  db.query(sql, [req.session.userId], (err, result) => {
    if (err) return res.status(500).json({ message: "Error en el servidor" });

    const userType = result[0]?.type;
    console.log(userType);
    if (userType === "admin") {
      return res.json({ message: "Admin autorizado" });
    } else {
      return res
        .status(403)
        .json({ message: "No tienes permisos de administrador" });
    }
  });
});

// -----  CRUD CLIENTES ADMIN ----
// Obtener todos los usuarios
app.get("/usuarios", (req, res) => {
  const sql = "SELECT * FROM usuarios";
  db.query(sql, (err, result) => {
    if (err) return res.status(500).json({ Error: err.message });
    res.json(result);
  });
});

// Actualizar un usuario
app.put("/usuarios/:id", (req, res) => {
  const { nombre, email } = req.body;
  const { id } = req.params;
  const sql = "UPDATE usuarios SET nombre = ?, email = ? WHERE id = ?";
  db.query(sql, [nombre, email, id], (err, result) => {
    if (err) return res.status(500).json({ Error: err.message });
    res.json({ message: "Usuario actualizado correctamente" });
  });
});

// Eliminar un usuario
app.delete("/usuarios/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM usuarios WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ Error: err.message });
    res.json({ message: "Usuario eliminado correctamente" });
  });
});

app.post("/usuarios", (req, res) => {
  const { nombre, email, password } = req.body;

  // Generar el hash de la contraseña
  bcrypt.hash(password, salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hashing password" });

    const sql =
      "INSERT INTO usuarios (nombre, email, password, type) VALUES (?, ?, ?, 'cliente')";
    db.query(sql, [nombre, email, hash], (err, result) => {
      if (err) return res.json({ Error: err });
      return res.json({ id: result.insertId, nombre, email }); // Devolver el usuario creado
    });
  });
});

// Endpoint para obtener todos los pedidos
app.get("/pedidos", (req, res) => {
  const sql =
    "SELECT id, id_cliente, precio_total, estado, fecha_creacion FROM pedidos"; // Asegúrate de que la tabla y los campos existen
  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error al obtener los pedidos" });
    }
    res.json(result);
  });
});

// Endpoint para obtener detalles de un pedido específico
app.get("/detallePedido/:id", (req, res) => {
  const { id } = req.params;

  const sqlPedido =
    "SELECT id, precio_total, estado, fecha_creacion, lista_productos, id_cliente FROM pedidos WHERE id = ?";

  db.query(sqlPedido, [id], (err, result) => {
    if (err)
      return res.status(500).json({ error: "Error al obtener el pedido" });

    if (result.length === 0) {
      return res.status(404).json({ error: "Pedido no encontrado" });
    }

    const pedido = result[0];

    console.log("AYUDAPORFAVORDEVERDAD--- ", pedido);
    res.json(pedido);
  });
});

//--------- DESDE EL ADMINN --------
// Endpoint para actualizar el estado de un pedido específico
app.put("/updateEstadoPedido/:id", (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  const sqlUpdateEstado = "UPDATE pedidos SET estado = ? WHERE id = ?";

  db.query(sqlUpdateEstado, [estado, id], (err, result) => {
    if (err) {
      console.error("Error al actualizar el estado del pedido:", err);
      return res.status(500).json({ error: "Error al actualizar el estado" });
    }

    res.json({ updated: true, message: "Estado del pedido actualizado" });
  });
});

// Endpoint para eliminar un pedido específico
app.delete("/eliminarPedido/:id", (req, res) => {
  const { id } = req.params;

  const sqlDeletePedido = "DELETE FROM pedidos WHERE id = ?";

  db.query(sqlDeletePedido, [id], (err, result) => {
    if (err) {
      console.error("Error al eliminar el pedido:", err);
      return res.status(500).json({ error: "Error al eliminar el pedido" });
    }

    res.json({ deleted: true, message: "Pedido eliminado correctamente" });
  });
});
