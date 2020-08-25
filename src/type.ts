export type User = {
    nombre_usuario: string
    contrasena: string
    token: string
    correo: string
    telefono: number
    id_usuario: number
    id_rol: number
}
export type Piscicola = {
    id_piscicolas: number
    id_usuario: number
    nombre_piscicola: string
    ubicacion: string
    descripcion: string
}
export type Estanque = {
    id_piscicolas: number
    id_estanque: number
    nombre_estanque: string
    descripcion: string
}
export type Sensor = {
    id_sensores: number
    id_estanque: number
    nombre_sensor: string
    unidad_medida: string
    descripcion: string
}
export type Asignacion = {
    id_asignacion: number
    id_piscicolas: number
    id_usuario: number
}

export type Roles = {
    id_rol: number
    rol: string
}

export type Mediciones = {
    id_mediciones: number
    id_sensores: number
    fecha: Date
    dato: number
}

export type DataCalculada = {
    id_sensores: number
    avg: number
    max : number
    min: number
    periodo: string
}