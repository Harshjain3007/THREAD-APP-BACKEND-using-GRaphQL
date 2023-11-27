import {createHmac,randomBytes}  from 'node:crypto'
import { prismaClient } from "../lib/db"
import JWT from 'jsonwebtoken'

const JWT_SECRET = '$uperM@n@123'

export interface CreateUserPayload {
    firstName: string,
    lastName: string,
    email: string,
    password:string
}

export interface GetUserTokenPayload {
    email: string;
    password: string
}


class UserService {

    private static generateHash(salt:string,password:string){
        const hashedpassword = createHmac('sha256',salt).update(password).digest('hex')
        return hashedpassword

    }

    public static  getUserById(id:string){
        return prismaClient.user.findUnique({where:{id}})
       
    }

    public static createUser(payload:CreateUserPayload){
        const {firstName,lastName,email,password}  = payload

        const salt = randomBytes(32).toString('hex')
       // const hashedpassword = createHmac('sha256',salt).update(password).digest('hex')
        const hashedpassword = UserService.generateHash(salt,password)
        return prismaClient.user.create({
            data:{
                firstName,
                lastName:lastName || '',
                email,
                salt,
                password: hashedpassword,

            }
        })

    }
    
    private static getUserByEmail(email:string){
        return prismaClient.user.findUnique({where:{email}})

    }
    public static async getUserToken(payload:GetUserTokenPayload){
        const {email,password} = payload
        const user = await UserService.getUserByEmail(email)
        if(!user) throw new Error('user not found');

        const userSalt = user.salt
        const usersHashedPassword = UserService.generateHash(userSalt,password)

        if(usersHashedPassword!==user.password)
        throw new Error('Incorrect Password')

        const token = JWT.sign({id:user.id,email:user.email},JWT_SECRET)
        return token
    }

    public static decodeJWTTOken(token:string){
        return JWT.verify(token,JWT_SECRET)
    }

}


export  default UserService