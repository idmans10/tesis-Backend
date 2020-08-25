"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const md5_typescript_1 = require("md5-typescript");
const cors_1 = __importDefault(require("cors"));
const fluture_1 = require("fluture");
const crypto_1 = __importDefault(require("crypto"));
const tools_1 = require("./tools");
// Create a new express app instance
const app = express_1.default();
app.use(body_parser_1.default.json());
app.use(cors_1.default());
// Create a new express app instance
// api login
app.post('/login', (req, res) => {
    const tokenSaved = (token) => (user) => {
        return tools_1.futureQuery(`UPDATE usuarios SET token = ? WHERE nombre_usuario= ? `, [token, user.nombre_usuario]);
    };
    const queryUser = (data) => {
        return tools_1.futureQuery(`SELECT * FROM usuarios WHERE nombre_usuario= ?`, [
            data.nombre_usuario
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    const validateUser = (results) => (data) => {
        // si existe el usuario
        if (results.length === 0)
            return fluture_1.reject('iv400'); // si no, devuelve que el usuario no existe
        const hash = md5_typescript_1.Md5.init(data.contrasena); // si la contraseña de la bd es igual al hash
        if (results[0].contrasena === hash)
            return fluture_1.resolve(results[0]);
        // si contraseña ok, devuelve el usuario con resolve
        else
            return fluture_1.reject('iv500'); // se devuelve con reject porque es un error
    };
    // acá va el flujo
    // Verificar que lleguen los valores esperados
    const data = tools_1.getProps(req.body, ['nombre_usuario', 'contrasena']); // se guarda en data lo que llega en el body
    const usersDb = fluture_1.chain(queryUser)(data); // busca en la BD el usuario guardado en data
    const user = tools_1.liftChain2(validateUser, usersDb, data); // valida que el usuario y la contraseña existan y sean correctos
    const token = crypto_1.default.randomBytes(32).toString('hex'); // si son correctos genera un token
    const isTokenSaved = fluture_1.chain(tokenSaved(token))(user); // guarda el token en la BD
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((code) => tools_1.handdleError(res)(code))((b) => res.send({ res: 200, msg: 'Login exitoso', data: { token } }))(isTokenSaved);
});
// api crear usuario
app.post('/create_user', (req, res) => {
    const validatePiscicola = ({ user, data }) => (piscicolasDb) => {
        if (user.id_rol === 4 && data.id_rol === 1 && data.id_piscicolas !== null)
            return fluture_1.reject('iv900'); // solo el admin podra crear usuario sin asignar piscicola
        if (piscicolasDb.length === 0 && data.id_rol !== 1)
            return fluture_1.reject('iv450');
        // No existe la piscicola
        else
            return fluture_1.resolve({ user, data }); // me retorna data
    };
    const createUser = ({ user, // datos del usuario logueado
    data // lo que llega del front
     }) => (usersDb) => {
        if (usersDb.length > 0)
            return fluture_1.reject('iv600'); // Si el nombre de usuario ya existe
        const isTrabajador = (rol) => rol === 3;
        const isGerente = (rol) => rol === 2;
        const isPisicultor = (rol) => rol === 1;
        const isAdmin = (rol) => rol === 4;
        if (isTrabajador(user.id_rol))
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (isPisicultor(user.id_rol) &&
            (isAdmin(data.id_rol) || isPisicultor(data.id_rol)))
            return fluture_1.reject('iv999'); // Permisos insuficientes - si el rol es pisicultor
        if (isGerente(user.id_rol) &&
            (isAdmin(data.id_rol) ||
                isPisicultor(data.id_rol) ||
                isGerente(data.id_rol)))
            return fluture_1.reject('iv999'); // si el rol es gerente
        return tools_1.futureQuery('INSERT INTO usuarios (nombre_usuario, contrasena, id_rol, correo, telefono) VALUES (?, ?, ?, ?, ?)', [
            data.nombre_usuario,
            md5_typescript_1.Md5.init(data.contrasena),
            data.id_rol,
            data.correo,
            data.telefono
        ]);
    };
    const createAsignacion = ({ user, data }) => (isCreatedUser) => {
        if (user.id_rol === 4 && data.id_piscicolas == null)
            return fluture_1.resolve(true);
        else
            return tools_1.futureQuery('INSERT INTO asignacion (id_piscicolas, id_usuario) VALUES (?, ?)', [data.id_piscicolas, isCreatedUser.insertId]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    console.log(req.body);
    const data = tools_1.getPropsAuth(req.body, [
        'nombre_usuario',
        'contrasena',
        'id_rol',
        'correo',
        'telefono',
        'id_piscicolas'
    ])(loggedUser); // verifica que los datos del nuevo usuario esten completos y adicional guarda los datos del usuario logueado
    const usersDb = fluture_1.chain(tools_1.queryUser)(data); // se busca el nuevo usuario en la BD
    const piscicolasDb = fluture_1.chain(tools_1.queryPiscicolaId)(data); // se busca la Piscicola que se asigno en el front
    const user = tools_1.liftChain2(validatePiscicola, data, piscicolasDb); // valido que la piscicola exista y pertenezca al usuario logueado
    const isCreatedUser = tools_1.liftChain2(createUser, user, usersDb); // valida que el usuario no exista y lo crea segun los permisos del usuario logueado
    const asignacion = tools_1.liftChain2(createAsignacion, data, isCreatedUser); // inserta la asignacion del usuario creado y su respectiva piscicola
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Usuario creado exitosamente' }))(asignacion);
});
// api ver mediciones
app.post('/mediciones', (req, res) => {
    const queryTableMediciones = (data) => {
        return tools_1.futureQuery(`SELECT * FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?) AND (fecha BETWEEN ? AND ?)`, [data.data.id_estanque, data.data.initDate, data.data.finalDate]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['id_estanque', 'initDate', 'finalDate'])(loggedUser); // verifica que se especifique los rangos de fecha
    const medicionesDb = fluture_1.chain(queryTableMediciones)(data); // se busca las mediciones en la DB
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({
        res: 200,
        msg: 'Data mediciones obtenida exitosamente',
        data: b
    }))(medicionesDb);
});
/* // api ver graphs
app.post('/graphs', (req, res) => {
  const queryTableMediciones = (data: {
   data: { id_estanque: number }
 }) => {
   return futureQuery(
     `SELECT * FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?)`,
     [data.data.id_estanque]
   ) as FutureInstance<string, Array<Mediciones>> // valor futuro que puede ser tipo string o tipo array usuarios
 }

 // acá va el flujo
 const loggedUser = auth(req.headers) // verifica que el usuario exista con el token
 const data = getPropsAuth(req.body, ['id_estanque'])(
   loggedUser
 ) // verifica que se especifique los rangos de fecha
 const medicionesDb = chain(queryTableMediciones)(data) // se busca las mediciones en la DB
 // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
 fork((a: string) => handdleError(res)(a))((b) =>
   res.send({
     res: 200,
     msg: 'Data mediciones obtenida exitosamente',
     data: b
   })
 )(medicionesDb)
})

 */
// api ver reporte calculado
app.post('/data_calculada', (req, res) => {
    const concatenar = (avgsemana) => (report) => {
        return fluture_1.resolve(avgsemana.concat(report));
    };
    const queryDataCalculada = (data) => {
        const mes = tools_1.futureQuery(`SELECT id_sensores, avg(dato), max(dato), min(dato), 'mes' AS periodo FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?) AND (fecha BETWEEN DATE(ADDDATE(CURDATE(), INTERVAL -30 DAY)) AND DATE(DATE_SUB(CURDATE(), INTERVAL 0 DAY))) group by id_sensores`, [data.data.id_estanque]);
        const semana = tools_1.futureQuery(`SELECT id_sensores, avg(dato), max(dato), min(dato), 'semana' AS periodo FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?) AND (fecha BETWEEN DATE(ADDDATE(CURDATE(), INTERVAL -7 DAY)) AND DATE(DATE_SUB(CURDATE(), INTERVAL 0 DAY))) group by id_sensores`, [data.data.id_estanque]);
        const messemana = (tools_1.liftChain2(concatenar, mes, semana));
        const ayer = tools_1.futureQuery(`SELECT id_sensores, avg(dato), max(dato), min(dato), 'ayer' AS periodo FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?) AND (fecha BETWEEN DATE(ADDDATE(CURDATE(), INTERVAL -1 DAY)) AND DATE(DATE_SUB(CURDATE(), INTERVAL 0 DAY))) group by id_sensores`, [data.data.id_estanque]);
        const messemanaayer = (tools_1.liftChain2(concatenar, messemana, ayer));
        const hoy = tools_1.futureQuery(`SELECT id_sensores, avg(dato), max(dato), min(dato), 'hoy' AS periodo FROM mediciones WHERE id_sensores IN (SELECT id_sensores FROM sensores WHERE id_estanque =?) AND (fecha > DATE_SUB(CURDATE(), INTERVAL 0 DAY)) group by id_sensores`, [data.data.id_estanque]);
        const messemanaayerhoy = (tools_1.liftChain2(concatenar, messemanaayer, hoy));
        return (messemanaayerhoy);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['id_estanque'])(loggedUser); // verifica que se especifique los rangos de fecha
    const dataCalculada = fluture_1.chain(queryDataCalculada)(data); // se hacen los querys y se concatenan
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({
        res: 200,
        msg: 'Data mediciones obtenida exitosamente',
        data: b
    }))(dataCalculada);
});
// api eliminar usuario
app.post('/delete_user', (req, res) => {
    const deleteUser = (data) => (usersDb) => {
        if (usersDb.length === 0)
            return fluture_1.reject('iv400'); // el nombre de usuario no existe
        if (data.data.id_rol !== usersDb[0].id_rol)
            return fluture_1.reject('iv300'); // si modifica el rol de ese usuario
        if (data.user.id_rol === 3)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (data.user.id_rol === 1 &&
            (data.data.id_rol === 4 || data.data.id_rol === 1))
            return fluture_1.reject('iv999'); // si el rol es pisicultor
        if (data.user.id_rol === 2 &&
            (data.data.id_rol === 4 ||
                data.data.id_rol === 1 ||
                data.data.id_rol === 2))
            return fluture_1.reject('iv999'); // si el rol es gerente
        return tools_1.futureQuery(`DELETE FROM usuarios WHERE id_usuario=?`, [
            usersDb[0].id_usuario
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['nombre_usuario', 'id_rol'])(loggedUser); // verifica que se especifique el nombre de usuario a eliminar y adicional guarda los datos del usuario logueado
    const usersDb = fluture_1.chain(tools_1.queryUser)(data); // se busca el usuario a eliminar en la BD
    const isDeletedUser = tools_1.liftChain2(deleteUser, data, usersDb); // valida que el usuario exista y lo elimina segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Usuario eliminado exitosamente' }))(isDeletedUser);
});
// api editar usuario
app.post('/edit_user', (req, res) => {
    const editUser = (data) => (usersDb) => {
        if (usersDb.length === 0)
            return fluture_1.reject('iv400'); // Si el nombre de usuario no existe
        if (usersDb[0].id_rol !== data.data.id_rol)
            return fluture_1.reject('iv300'); // si modifica el rol de ese usuario
        if (data.user.id_rol === 3 &&
            data.data.nombre_usuario !== data.user.nombre_usuario)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (data.user.id_rol === 1 &&
            (data.data.id_rol === 4 ||
                (data.data.id_rol === 1 &&
                    data.data.nombre_usuario !== data.user.nombre_usuario)))
            return fluture_1.reject('iv999'); // si el rol es pisicultor
        if (data.user.id_rol === 2 &&
            (data.data.id_rol === 4 ||
                data.data.id_rol === 1 ||
                (data.data.id_rol === 2 &&
                    data.data.nombre_usuario !== data.user.nombre_usuario)))
            return fluture_1.reject('iv999'); // si el rol es gerente
        if (data.user.nombre_usuario === data.data.nombre_usuario) {
            return tools_1.futureQuery(`UPDATE usuarios SET contrasena = ?, id_rol = ?, correo = ?, telefono = ? WHERE id_usuario= ? `, [
                md5_typescript_1.Md5.init(data.data.contrasena),
                data.data.id_rol,
                data.data.correo,
                data.data.telefono,
                usersDb[0].id_usuario
            ]);
        }
        return tools_1.futureQuery(`UPDATE usuarios INNER JOIN asignacion ON usuarios.id_usuario = asignacion.id_usuario SET usuarios.contrasena = ?, usuarios.id_rol = ?, usuarios.correo = ?, usuarios.telefono = ?, asignacion.id_piscicolas=? WHERE usuarios.id_usuario= ? `, [
            md5_typescript_1.Md5.init(data.data.contrasena),
            data.data.id_rol,
            data.data.correo,
            data.data.telefono,
            data.data.id_piscicolas,
            usersDb[0].id_usuario
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    console.log(req.body);
    const data = tools_1.getPropsAuth(req.body, [
        'nombre_usuario',
        'contrasena',
        'id_rol',
        'correo',
        'telefono',
        'id_piscicolas'
    ])(loggedUser); // verifica que los datos del usuario a editar esten completos y adicional guarda los datos del usuario logueado
    const usersDb = fluture_1.chain(tools_1.queryUser)(data); // se busca el usuario a editar en la BD
    const isEditedUser = tools_1.liftChain2(editUser, data, usersDb); // valida que el usuario exista y lo edita segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Usuario editado exitosamente' }))(isEditedUser);
});
// api crear piscicola
app.post('/create_piscicola', (req, res) => {
    const createPiscicola = (data) => (piscicolasDb) => {
        if (piscicolasDb.length > 0)
            return fluture_1.reject('iv650'); // Si el nombre de la piscicola ya existe
        if (data.user.id_rol === 4 ||
            data.user.id_rol === 3 ||
            data.user.id_rol === 2)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador, gerente o admin, no puede crear piscicolas
        return tools_1.futureQuery('INSERT INTO piscicolas (nombre_piscicola, ubicacion, id_usuario, descripcion) VALUES (?, ?, ?, ?)', [
            data.data.nombre_piscicola,
            data.data.ubicacion,
            data.user.id_usuario,
            data.data.descripcion
        ]);
    };
    const createAsignacion = ({ user, data }) => (isCreatedPiscicola) => {
        return tools_1.futureQuery('INSERT INTO asignacion (id_piscicolas, id_usuario) VALUES (?, ?)', [isCreatedPiscicola.insertId, user.id_usuario]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    console.log(req.body);
    const data = tools_1.getPropsAuth(req.body, [
        'nombre_piscicola',
        'ubicacion',
        'descripcion'
    ])(loggedUser); // verifica que los datos del nuevo piscicultivo esten completos y adicional guarda los datos del usuario logueado
    const piscicolasDb = fluture_1.chain(tools_1.queryPiscicola)(data); // se busca la nueva piscicola en la BD
    const isCreatedPiscicola = tools_1.liftChain2(createPiscicola, data, piscicolasDb); // valida que la piscicola no exista y la crea segun los permisos del usuario logueado
    const asignacion = tools_1.liftChain2(createAsignacion, data, isCreatedPiscicola); // inserta la asignacion de la piscicola creada y su respectiva  usuario loggeado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Piscicola creada exitosamente' }))(asignacion);
});
// api eliminar piscicola
app.post('/delete_piscicola', (req, res) => {
    const deletePiscicola = (data) => (piscicolasDb) => {
        if (piscicolasDb.length === 0)
            return fluture_1.reject('iv450'); // el nombre de la piscicola no existe
        if (data.user.id_rol === 3)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (piscicolasDb[0].id_piscicolas !== data.data.id_piscicolas)
            return fluture_1.reject('iv300');
        return tools_1.futureQuery(`DELETE FROM piscicolas WHERE id_piscicolas=?`, [
            piscicolasDb[0].id_piscicolas
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['nombre_piscicola', 'id_piscicolas'])(loggedUser); // verifica que se especifique el nombre de la piscicola a eliminar y adicional guarda los datos del usuario logueado
    const piscicolasDb = fluture_1.chain(tools_1.queryPiscicola)(data); // se busca la piscicola a eliminar en la BD
    const isDeletedPiscicola = tools_1.liftChain2(deletePiscicola, data, piscicolasDb); // valida que la piscicola exista y lo elimina segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Piscicola eliminada exitosamente' }))(isDeletedPiscicola);
});
// api editar piscicola
app.post('/edit_piscicola', (req, res) => {
    const editPiscicola = (data) => (piscicolasDb) => {
        if (piscicolasDb.length === 0)
            return fluture_1.reject('iv450'); // el nombre de piscicola no existe
        if (data.user.id_rol === 3)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (piscicolasDb[0].id_piscicolas !== data.data.id_piscicolas)
            return fluture_1.reject('iv300'); // si el id de la piscicola del front no es el mismo de la BD
        return tools_1.futureQuery(`UPDATE piscicolas SET piscicolas.nombre_piscicola = ?, piscicolas.descripcion = ?, piscicolas.ubicacion = ? WHERE id_piscicolas= ? `, [
            data.data.nombre_piscicola,
            data.data.descripcion,
            data.data.ubicacion,
            piscicolasDb[0].id_piscicolas
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    console.log(req.body);
    const data = tools_1.getPropsAuth(req.body, [
        'id_piscicolas',
        'nombre_piscicola',
        'ubicacion',
        'descripcion'
    ])(loggedUser); // verifica que los datos del usuario a editar esten completos y adicional guarda los datos del usuario logueado
    const piscicolasDb = fluture_1.chain(tools_1.queryPiscicola)(data); // se busca el usuario a editar en la BD
    const isEditedPiscicola = tools_1.liftChain2(editPiscicola, data, piscicolasDb); // valida que el usuario exista y lo edita segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Piscicola editada exitosamente' }))(isEditedPiscicola);
});
// api crear estanque
app.post('/create_estanque', (req, res) => {
    const validatePiscicolaId = (data) => (piscicolasDb) => {
        if (piscicolasDb.length === 0)
            return fluture_1.reject('iv300');
        // si no, devuelve dato invalido
        else
            return fluture_1.resolve(data); // me retorna data
    };
    const createEstanque = (data) => (estanquesDb) => {
        if (estanquesDb.length > 0)
            return fluture_1.reject('iv670'); // Si el nombre del estanque ya existe
        if (data.user.id_rol === 3 || data.user.id_rol === 4)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador o admin, no puede crear estanques
        return tools_1.futureQuery('INSERT INTO estanque (nombre_estanque, id_piscicolas, descripcion) VALUES (?, ?, ?)', [
            data.data.nombre_estanque,
            data.data.id_piscicolas,
            data.data.descripcion
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    console.log(req.body);
    const data = tools_1.getPropsAuth(req.body, [
        'id_piscicolas',
        'nombre_estanque',
        'descripcion'
    ])(loggedUser); // verifica que los datos del nuevo estanque esten completos y adicional guarda los datos del usuario logueado
    const estanquesDb = fluture_1.chain(tools_1.queryEstanque)(data); // se busca el nuevo estanque en la BD
    const piscicolasDb = fluture_1.chain(tools_1.queryPiscicolaId)(data); // se busca la Piscicola que se asigno en el front
    const estanque = tools_1.liftChain2(validatePiscicolaId, data, piscicolasDb); // valido que la piscicola exista y pertenezca al usuario logueado
    const isCreatedEstanque = tools_1.liftChain2(createEstanque, estanque, estanquesDb); // valida que el estanque no exista y la crea segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Estanque creado exitosamente' }))(isCreatedEstanque);
});
// api eliminar estanque
app.post('/delete_estanque', (req, res) => {
    const deleteEstanque = (data) => (estanquesDb) => {
        if (estanquesDb.length === 0)
            return fluture_1.reject('iv470'); // el nombre del estanque no existe
        if (data.user.id_rol === 3 || data.user.id_rol === 4)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (estanquesDb[0].id_estanque !== data.data.id_estanque)
            return fluture_1.reject('iv300');
        return tools_1.futureQuery(`DELETE FROM estanque WHERE id_estanque=?`, [
            estanquesDb[0].id_estanque
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['nombre_estanque', 'id_estanque'])(loggedUser); // verifica que se especifique el nombre de la piscicola a eliminar y adicional guarda los datos del usuario logueado
    const estanquesDb = fluture_1.chain(tools_1.queryEstanque)(data); // se busca la piscicola a eliminar en la BD
    const isDeletedEstanque = tools_1.liftChain2(deleteEstanque, data, estanquesDb); // valida que la piscicola exista y lo elimina segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Estanque eliminado exitosamente' }))(isDeletedEstanque);
});
// api editar estanque
app.post('/edit_estanque', (req, res) => {
    const editEstanque = (data) => (estanquesDb) => {
        if (estanquesDb.length === 0)
            return fluture_1.reject('iv470'); // el nombre de piscicola no existe
        if (data.user.id_rol === 3)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        if (estanquesDb[0].id_estanque !== data.data.id_estanque)
            return fluture_1.reject('iv300');
        return tools_1.futureQuery(`UPDATE estanque SET estanque.nombre_estanque = ?, estanque.descripcion = ? WHERE id_estanque= ? `, [
            data.data.nombre_estanque,
            data.data.descripcion,
            estanquesDb[0].id_estanque
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, [
        'id_estanque',
        'nombre_estanque',
        'descripcion'
    ])(loggedUser); // verifica que los datos del usuario a editar esten completos y adicional guarda los datos del usuario logueado
    const estanquesDb = fluture_1.chain(tools_1.queryEstanque)(data); // se busca el usuario a editar en la BD
    const isEditedEstanque = tools_1.liftChain2(editEstanque, data, estanquesDb); // valida que el usuario exista y lo edita segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Estanque editado exitosamente' }))(isEditedEstanque);
});
// api crear sensores
app.post('/create_sensor', (req, res) => {
    const queryEstanqueId = (data) => {
        return tools_1.futureQuery(`SELECT * FROM estanque WHERE id_piscicolas IN (SELECT id_piscicolas FROM asignacion WHERE id_usuario= ?) AND id_estanque=?`, [data.user.id_usuario, data.data.id_estanque]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    const validateEstanqueId = (data) => (estanquesDb) => {
        if (estanquesDb.length === 0)
            return fluture_1.reject('iv300');
        // si no, devuelve dato invalido
        else
            return fluture_1.resolve(data); // me retorna data
    };
    const createSensor = (data) => (sensoresDb) => {
        if (sensoresDb.length > 0)
            return fluture_1.reject('iv690'); // Si el nombre del sensor ya existe
        if (data.user.id_rol === 3 || data.user.id_rol === 4)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador o admi, no puede crear sensores
        return tools_1.futureQuery('INSERT INTO sensores (nombre_sensor, id_estanque, unidad_medida, descripcion) VALUES (?, ?, ?, ?)', [
            data.data.nombre_sensor,
            data.data.id_estanque,
            data.data.unidad_medida,
            data.data.descripcion
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, [
        'id_estanque',
        'nombre_sensor',
        'unidad_medida',
        'descripcion'
    ])(loggedUser); // verifica que los datos del nuevo estanque esten completos y adicional guarda los datos del usuario logueado
    const sensoresDb = fluture_1.chain(tools_1.querySensor)(data); // se busca el nuevo sensor en la BD
    const estanquesDb = fluture_1.chain(queryEstanqueId)(data); // se busca el estanque que se asigno en el front
    const estanque = tools_1.liftChain2(validateEstanqueId, data, estanquesDb); // valido que el estanque exista y pertenezca al usuario logueado
    const isCreatedSensor = tools_1.liftChain2(createSensor, estanque, sensoresDb); // valida que el sensor no exista y la crea segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Sensor creado exitosamente' }))(isCreatedSensor);
});
// api eliminar sensor
app.post('/delete_sensor', (req, res) => {
    const deleteSensor = (data) => (sensoresDb) => {
        if (sensoresDb.length === 0)
            return fluture_1.reject('iv490'); // el nombre del sensor no existe
        if (sensoresDb[0].id_sensores !== data.data.id_sensores)
            return fluture_1.reject('iv300');
        if (data.user.id_rol === 3 || data.user.id_rol === 4)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        return tools_1.futureQuery(`DELETE FROM sensores WHERE id_sensores=?`, [
            sensoresDb[0].id_sensores
        ]);
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['id_sensores', 'nombre_sensor'])(loggedUser); // verifica que se especifique el sensor a eliminar y adicional guarda los datos del usuario logueado
    const sensoresDb = fluture_1.chain(tools_1.querySensor)(data); // se busca el sensor a eliminar en la BD
    const isDeletedSensor = tools_1.liftChain2(deleteSensor, data, sensoresDb); // valida que el sensor exista y lo elimina segun los permisos del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Sensor eliminado exitosamente' }))(isDeletedSensor);
});
// api ver usuarios
app.post('/users', (req, res) => {
    const queryTableUser = (loggedUser) => {
        if (loggedUser.id_rol === 1) {
            return tools_1.futureQuery(`SELECT * FROM usuarios WHERE id_usuario IN (SELECT id_usuario FROM asignacion WHERE id_piscicolas IN (SELECT id_piscicolas FROM asignacion WHERE id_usuario=?)) AND (id_rol=3 OR id_rol=2)`, [loggedUser.id_usuario]);
        }
        if (loggedUser.id_rol === 2) {
            return tools_1.futureQuery(`SELECT * FROM usuarios WHERE id_usuario IN (SELECT id_usuario FROM asignacion WHERE id_piscicolas IN (SELECT id_piscicolas FROM asignacion WHERE id_usuario=?)) AND id_rol=3`, [loggedUser.id_usuario]);
        }
        if (loggedUser.id_rol === 3)
            return fluture_1.reject('iv999'); // Permisos insuficientes--- si el rol es trabajador
        return tools_1.futureQuery(`SELECT * FROM usuarios`, [
            loggedUser.id_usuario
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const usersDb = fluture_1.chain(queryTableUser)(loggedUser); // se buscan los usuarios en la base de datos según el id del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Data usuarios obtenidos exitosamente', data: b }))(usersDb);
});
// api ver roles
app.post('/roles', (req, res) => {
    const queryTableRoles = (loggedUser) => {
        return tools_1.futureQuery(`SELECT * FROM rol`, [
            loggedUser.id_usuario
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const rolesDb = fluture_1.chain(queryTableRoles)(loggedUser); // se buscan las piscicolas en la base de datos (para todos los usuarios logueados)
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({
        res: 200,
        msg: 'Datos roles obtenidos exitosamente',
        data: b
    }))(rolesDb);
});
// api ver piscicolas
app.post('/piscicolas', (req, res) => {
    const queryTablePiscicolas = (loggedUser) => {
        if (loggedUser.id_rol === 4)
            return tools_1.futureQuery(`SELECT * FROM piscicolas`, [
                loggedUser.id_usuario
            ]);
        else
            return tools_1.futureQuery(`SELECT * FROM piscicolas WHERE id_piscicolas IN (SELECT id_piscicolas FROM asignacion WHERE id_usuario=?)`, [loggedUser.id_usuario]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const piscicolasDb = fluture_1.chain(queryTablePiscicolas)(loggedUser); // se buscan las piscicolas en la base de datos (para todos los usuarios logueados)
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({
        res: 200,
        msg: 'Datos piscicolas obtenidos exitosamente',
        data: b
    }))(piscicolasDb);
});
// api ver estanques
app.post('/estanques', (req, res) => {
    const queryTableEstanques = (data) => {
        return tools_1.futureQuery(`SELECT * FROM estanque WHERE id_piscicolas=?`, [
            data.data.id_piscicolas
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['id_piscicolas'])(loggedUser); // verifica que se especifique la pisicola y adicional guarda los datos del usuario logueado
    const estanquesDb = fluture_1.chain(queryTableEstanques)(data); // se busca el nuevo estanque en la BD
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Data estanques obtenida exitosamente', data: b }))(estanquesDb);
});
// api ver sensores
app.post('/sensores', (req, res) => {
    const queryTableSensores = (data) => {
        return tools_1.futureQuery(`SELECT * FROM sensores WHERE id_estanque=?`, [
            data.data.id_estanque
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const data = tools_1.getPropsAuth(req.body, ['id_estanque'])(loggedUser); // verifica que se especifique la pisicola y adicional guarda los datos del usuario logueado
    const sensoresDb = fluture_1.chain(queryTableSensores)(data); // se busca el nuevo estanque en la BD
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Data sensores obtenida exitosamente', data: b }))(sensoresDb);
});
// api ver datos del loggeado
app.post('/myuser', (req, res) => {
    const queryTableUser = (loggedUser) => {
        return tools_1.futureQuery(`SELECT * FROM usuarios WHERE id_usuario= ?`, [
            loggedUser.id_usuario
        ]); // valor futuro que puede ser tipo string o tipo array usuarios
    };
    // acá va el flujo
    const loggedUser = tools_1.auth(req.headers); // verifica que el usuario exista con el token
    const usersDb = fluture_1.chain(queryTableUser)(loggedUser); // se buscan los usuarios en la base de datos según el id del usuario logueado
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Data usuario obtenidos exitosamente', data: b }))(usersDb);
    // {x, max, min, reporte} reporte obtenido de bd
});
app.post('/create_mediciones', (req, res) => {
    const arrayData = (data) => {
        if (!data.data)
            console.log('Recepción de datos: ok');
        else if (data.data === "ffff")
            return fluture_1.reject('iv999');
        else {
            const dataChar = data.data.toString().split('aa').map((x) => +x);
            console.log("dataCharrecibidook:");
            console.log(dataChar);
            // return resolve(dataChar) as FutureInstance<string, Array<any>>
            return (dataChar);
        }
    };
    const adaptData = (data) => {
        data[0] = data[0] / 100; // temp
        data[1] = data[1] / 100; // ph
        data[2] = data[2]; // nivel
        data[3] = data[3] / 100; // od
        data[4] = data[4] / 100; // turbidez
        return fluture_1.resolve(data);
    };
    const createMedicion = (adaptedData) => {
        const hoy = new Date();
        const fecha = hoy.getFullYear() + "-" + (hoy.getMonth() + 1) + "-" + hoy.getDate();
        const hora = (hoy.getHours()) + ":" + hoy.getMinutes() + ":" + hoy.getSeconds();
        // var fecha= "2020-5-20";
        const date = fecha + " " + hora;
        return tools_1.futureQuery('INSERT INTO mediciones (id_sensores, fecha, dato) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?)', [
            adaptedData[5],
            date,
            adaptedData[0],
            adaptedData[6],
            date,
            adaptedData[1],
            adaptedData[7],
            date,
            adaptedData[2],
            adaptedData[8],
            date,
            adaptedData[3],
            adaptedData[9],
            date,
            adaptedData[4],
        ]);
    };
    // acá va el flujo
    const data = arrayData(req.body); // recibir la data del body (enviada por loriot) y pasarla a un array
    const adaptedData = adaptData(data); // adaptar la data
    const isCreatedMedicion = fluture_1.chain(createMedicion)(adaptedData); // inserta la data adaptada a la bd
    // funcion que mete dos variables en 1
    // insertar a la bd ... enviar 2 variables
    // sacar informacion del ultimo contenedor. Si hay un reject entra a handdleError y si no envia otra respuesta
    fluture_1.fork((a) => tools_1.handdleError(res)(a))((b) => res.send({ res: 200, msg: 'Medicion creado exitosamente' }))(isCreatedMedicion);
});
app.listen(3000, () => {
    console.log('App is listening on port 3000!');
});
//# sourceMappingURL=index.js.map