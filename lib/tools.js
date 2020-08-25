"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.queryPiscicolaId = exports.querySensor = exports.queryEstanque = exports.queryPiscicola = exports.auth = exports.getPropsAuth = exports.queryToken = exports.queryUser = exports.join = exports.liftChain2 = exports.getProps = exports.futureQuery = exports.handdleError = exports.connection = void 0;
const mysql_1 = __importDefault(require("mysql"));
const fluture_1 = require("fluture");
exports.connection = mysql_1.default.createConnection({
    host: 'localhost',
    user: 'root',
    password: '20101073020Ud',
    database: 'bdpiscicultivo'
});
exports.connection.connect();
exports.handdleError = (res) => (code) => {
    if (code === 'iv001')
        res.send({ res: 'iv001', msg: 'Error interno en la base de datos' });
    else if (code === 'iv300')
        res.send({ res: 'iv300', msg: 'Datos inválidos' });
    else if (code === 'iv400')
        res.send({ res: 'iv400', msg: 'No existe el usuario' });
    else if (code === 'iv450')
        res.send({ res: 'iv450', msg: 'No existe la piscicola' });
    else if (code === 'iv470')
        res.send({ res: 'iv470', msg: 'No existe el estanque' });
    else if (code === 'iv490')
        res.send({ res: 'iv490', msg: 'No existe el sensor' });
    else if (code === 'iv500')
        res.send({ res: 'iv500', msg: 'Credenciales incorrectas' });
    else if (code === 'iv600')
        res.send({ res: 'iv600', msg: 'El usuario ya existe' });
    else if (code === 'iv650')
        res.send({ res: 'iv650', msg: 'La piscicola ya existe' });
    else if (code === 'iv670')
        res.send({ res: 'iv670', msg: 'El estanque ya existe' });
    else if (code === 'iv690')
        res.send({ res: 'iv690', msg: 'El sensor ya existe' });
    else if (code === 'iv800')
        res.send({ res: 'iv800', msg: 'Error de autenticación' });
    else if (code === 'iv900')
        res.send({ res: 'iv900', msg: 'No es posible asignar piscicola' });
    else if (code === 'iv999')
        res.send({ res: 'iv999', msg: 'Permisos insuficientes' });
    else
        res.send({ res: code, msg: 'Error no definido' });
};
// se utiiza para realizar querys de manera general
exports.futureQuery = (query, params) => fluture_1.Future((rej, res) => {
    exports.connection.query(query, params, (err, result) => {
        err && console.log(err);
        err ? rej('iv001') : res(result || true);
    });
    return () => { };
});
exports.getProps = (body, props) => {
    const propsExist = props.map((prop) => prop in body).every((a) => a);
    return propsExist
        ? fluture_1.resolve(props.reduce((a, b) => (Object.assign(Object.assign({}, a), { [b]: body[b] })), {}))
        : fluture_1.reject('iv300');
};
exports.liftChain2 = (g, f1, f2) => exports.join(fluture_1.ap(f2)(fluture_1.map(g)(f1)));
exports.join = (f) => {
    return fluture_1.chain((a) => a)(f);
};
exports.queryUser = (data) => {
    return exports.futureQuery(`SELECT * FROM usuarios WHERE nombre_usuario= ?`, [
        data.data.nombre_usuario
    ]); // valor futuro que puede ser tipo string o tipo array usuarios
};
exports.queryToken = (token) => {
    return exports.futureQuery(`SELECT * FROM usuarios WHERE token= ?`, [
        token
    ]); // valor futuro que puede ser tipo string o tipo array usuarios
};
exports.getPropsAuth = (body, props) => (auth) => {
    const propsExist = props.map((prop) => prop in body).every((a) => a);
    console.log(propsExist);
    const validProps = (user) => propsExist
        ? fluture_1.resolve({
            user,
            data: props.reduce((a, b) => (Object.assign(Object.assign({}, a), { [b]: body[b] })), {})
        })
        : fluture_1.reject('iv300');
    return fluture_1.chain(validProps)(auth);
};
exports.auth = (headers) => {
    // sacar de los header, la autorizacion  authorization:
    if (!headers.authorization)
        return fluture_1.reject('iv800'); // se verifica que em headers haya un token
    // autohir = token.... se busca en la bd .. con un select*from (queryToken)
    const istoken = exports.queryToken(headers.authorization);
    const validateUser = (results) => {
        if (results.length > 0)
            return fluture_1.resolve(results[0]); // si existe el usuario
        else
            return fluture_1.reject('iv500'); // si no, devuelve que el usuario no existe o sea credenciales incorrectas
    };
    const thisUser = fluture_1.chain(validateUser)(istoken);
    return thisUser;
};
exports.queryPiscicola = (data) => {
    return exports.futureQuery(`SELECT * FROM piscicolas WHERE nombre_piscicola= ?`, [
        data.data.nombre_piscicola
    ]); // valor futuro que puede ser tipo string o tipo array usuarios
};
exports.queryEstanque = (data) => {
    return exports.futureQuery(`SELECT * FROM estanque WHERE nombre_estanque= ?`, [
        data.data.nombre_estanque
    ]); // valor futuro que puede ser tipo string o tipo array usuarios
};
exports.querySensor = (data) => {
    return exports.futureQuery(`SELECT * FROM sensores WHERE nombre_sensor= ?`, [
        data.data.nombre_sensor
    ]); // valor futuro que puede ser tipo string o tipo array usuarios
};
exports.queryPiscicolaId = (data) => {
    if (data.user.id_rol !== 4)
        return exports.futureQuery(`SELECT * FROM asignacion WHERE id_piscicolas = ? AND id_usuario= ?`, [data.data.id_piscicolas, data.user.id_usuario]); // valor futuro que puede ser tipo string o tipo array usuarios
    else
        return exports.futureQuery(`SELECT * FROM asignacion WHERE id_piscicolas = ?`, [data.data.id_piscicolas]);
};
//# sourceMappingURL=tools.js.map