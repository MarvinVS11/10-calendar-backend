const {response} = require('express');
const {validationResult}= require('express-validator')
const bcrypt = require('bcryptjs')
const Usuario = require('../models/Usuario')
const {generarJWT} = require('../helpers/jwt')


const crearUsuario = async(req, res= response)=>{
   const { email, password} =req.body;
   try {
    let usuario = await Usuario.findOne({email});
 
    
    if (usuario){
      return res.status(400).json({
        ok:false,
        msg:'Un usuario existe con ese correo'
      })
    }
     usuario = new Usuario(req.body);

     //Encriptar contrasenia
     const salt = bcrypt.genSaltSync();
     usuario.password= bcrypt.hashSync(password, salt);

     await usuario.save();
     //Generar JWT
const token = await generarJWT(usuario.id, usuario.name)

    res.status(201).json({
       ok:true,
       uid: usuario.id,
       name: usuario.name,
       token
       
     })
   } catch (error) {
    console.log(error);
    res.status(500).json({
      ok:false,
      msg: 'El usuario que intenta registrar ya encuentra registrado'
    })
   }

}
const loginUsuario= async(req, res= response)=>{

  
    const { email, password} =req.body;

    try {

      const usuario = await Usuario.findOne({email});
 
    
      if (!usuario){
        return res.status(400).json({
          ok:false,
          msg:'No existe ningun registro con ese email'
        })
      }
      //Confirmar Passwords
      const validPassword = bcrypt.compareSync(password, usuario.password)
      if(!validPassword){
        return res.status(400).json({
          ok:false,
          msg:'Password incorrecto'
        });
      }
     
         //Generar JWT
const token = await generarJWT(usuario.id, usuario.name)


        res.json({
          ok:true,
          uid:usuario.id,
          name:usuario.name,
          token
        })
    } catch (error) {
      res.status(500).json({
        ok:false,
        msg:'Pongase en contacto con el administrador'
      })
    }
  
};
const revalidarToken=async(req, res=response)=>{
   const {uid, name} = req;
   

   //Generar un nuevo token
   const token = await generarJWT(uid, name)
    res.json({
      ok:true, 
       token      
    })
};

module.exports={
    crearUsuario,
    loginUsuario,
    revalidarToken
}