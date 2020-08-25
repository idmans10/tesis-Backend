// herramientas
import { Response } from 'express'
import mysql from 'mysql'
import {
  Future,
  FutureInstance,
  resolve,
  reject,
  chain,
  map,
  ap
} from 'fluture'

import { User, Piscicola, Estanque, Sensor, Asignacion } from './type'

export const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '20101073020Ud',
  database: 'bdpiscicultivo'
})
connection.connect()

export const handdleError = (res: Response<any>) => (code: string) => {
  if (code === 'iv001')
    res.send({ res: 'iv001', msg: 'Error interno en la base de datos' })
  else if (code === 'iv300')
    res.send({ res: 'iv300', msg: 'Datos inválidos' })
  else if (code === 'iv400')
    res.send({ res: 'iv400', msg: 'No existe el usuario' })
  else if (code === 'iv450')
    res.send({ res: 'iv450', msg: 'No existe la piscicola' })
  else if (code === 'iv470')
    res.send({ res: 'iv470', msg: 'No existe el estanque' })
  else if (code === 'iv490')
    res.send({ res: 'iv490', msg: 'No existe el sensor' })
  else if (code === 'iv500')
    res.send({ res: 'iv500', msg: 'Credenciales incorrectas' })
  else if (code === 'iv600')
    res.send({ res: 'iv600', msg: 'El usuario ya existe' })
  else if (code === 'iv650')
    res.send({ res: 'iv650', msg: 'La piscicola ya existe' })
  else if (code === 'iv670')
    res.send({ res: 'iv670', msg: 'El estanque ya existe' })
  else if (code === 'iv690')
    res.send({ res: 'iv690', msg: 'El sensor ya existe' })
  else if (code === 'iv800')
    res.send({ res: 'iv800', msg: 'Error de autenticación' })
  else if (code === 'iv900')
    res.send({ res: 'iv900', msg: 'No es posible asignar piscicola' })
  else if (code === 'iv999')
    res.send({ res: 'iv999', msg: 'Permisos insuficientes' })
  else res.send({ res: code, msg: 'Error no definido' })
}
// se utiiza para realizar querys de manera general
export const futureQuery = (query: string, params: Array<any>) =>
  Future((rej, res) => {
    connection.query(query, params, (err, result) => {
      err && console.log(err)
      err ? rej('iv001') : res(result || true)
    })
    return () => {}
  })

export const getProps = <T extends string>(
  body: { [name: string]: any },
  props: T[]
) => {
  const propsExist = props.map((prop) => prop in body).every((a) => a)
  return propsExist
    ? resolve(
        props.reduce((a, b) => ({ ...a, [b]: body[b] }), {}) as {
          [K in T]: any
        }
      )
    : reject('iv300')
}
export const liftChain2 = <
  T extends FutureInstance<T1, T2>,
  T1,
  T2,
  U extends FutureInstance<T1, U2>,
  U2,
  V
>(
  g: (a: T2) => (b: U2) => FutureInstance<T1, V>,
  f1: T,
  f2: U
) => join(ap(f2)(map(g)(f1))) as FutureInstance<T1, V>

export const join = <T, V>(f: FutureInstance<T, FutureInstance<T, V>>) => {
  return chain((a: FutureInstance<T, V>) => a)(f)
}

export const queryUser = (data: { data: { nombre_usuario: string } }) => {
  return futureQuery(`SELECT * FROM usuarios WHERE nombre_usuario= ?`, [
    data.data.nombre_usuario
  ]) as FutureInstance<string, Array<User>> // valor futuro que puede ser tipo string o tipo array usuarios
}

export const queryToken = (token: string) => {
  return futureQuery(`SELECT * FROM usuarios WHERE token= ?`, [
    token
  ]) as FutureInstance<string, Array<User>> // valor futuro que puede ser tipo string o tipo array usuarios
}

export const getPropsAuth = <T extends string, U>(
  body: { [name: string]: any },
  props: T[]
) => (auth: FutureInstance<string, User>) => {
  const propsExist = props.map((prop) => prop in body).every((a) => a)

  console.log(propsExist)
  const validProps = (user: User) =>
    propsExist
      ? resolve({
          user,
          data: props.reduce((a, b) => ({ ...a, [b]: body[b] }), {}) as {
            [K in T]: any
          }
        })
      : reject('iv300')

  return chain(validProps)(auth)
}

export const auth = (headers: {
  authorization?: string
}): FutureInstance<string, User> => {
  // sacar de los header, la autorizacion  authorization:
  if (!headers.authorization) return reject('iv800') // se verifica que em headers haya un token
  // autohir = token.... se busca en la bd .. con un select*from (queryToken)
  const istoken = queryToken(headers.authorization)
  const validateUser = (results: Array<User>): FutureInstance<string, User> => {
    if (results.length > 0) return resolve(results[0]) // si existe el usuario
    else return reject('iv500') // si no, devuelve que el usuario no existe o sea credenciales incorrectas
  }
  const thisUser = chain(validateUser)(istoken)
  return thisUser
}

export const queryPiscicola = (data: {
  data: { nombre_piscicola: string }
}) => {
  return futureQuery(`SELECT * FROM piscicolas WHERE nombre_piscicola= ?`, [
    data.data.nombre_piscicola
  ]) as FutureInstance<string, Array<Piscicola>> // valor futuro que puede ser tipo string o tipo array usuarios
}

export const queryEstanque = (data: { data: { nombre_estanque: number } }) => {
  return futureQuery(`SELECT * FROM estanque WHERE nombre_estanque= ?`, [
    data.data.nombre_estanque
  ]) as FutureInstance<string, Array<Estanque>> // valor futuro que puede ser tipo string o tipo array usuarios
}

export const querySensor = (data: { data: { nombre_sensor: number } }) => {
  return futureQuery(`SELECT * FROM sensores WHERE nombre_sensor= ?`, [
    data.data.nombre_sensor
  ]) as FutureInstance<string, Array<Sensor>> // valor futuro que puede ser tipo string o tipo array usuarios
}

export const queryPiscicolaId = (data: {
  user: { id_usuario: number, id_rol:number }
  data: { id_piscicolas: number }
}) => {
   if (data.user.id_rol!==4) return futureQuery(
    `SELECT * FROM asignacion WHERE id_piscicolas = ? AND id_usuario= ?`,
    [data.data.id_piscicolas, data.user.id_usuario]
  ) as FutureInstance<string, Array<Asignacion>> // valor futuro que puede ser tipo string o tipo array usuarios
  else return futureQuery(
    `SELECT * FROM asignacion WHERE id_piscicolas = ?`,
    [data.data.id_piscicolas]
  ) as FutureInstance<string, Array<Asignacion>>

}
