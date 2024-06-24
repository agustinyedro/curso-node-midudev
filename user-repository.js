import DBlocal from "db-local";
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { SALT_ROUNDS } from "./config.js";

const { Schema } = new DBlocal({ path: "./db" });

const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});

export class UserRepository {
  static async create({ username, password }) {
    // 1. Validaciones de usuario y contraseña
    Validaciones.username(username);
    Validaciones.password(password);

    // 2. asegurar que el usuario no exista

    const user = User.findOne({ username });
    if (user) throw new Error("User already exists");

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    User.create({ _id: id, username, password: hashedPassword }).save();
    return id;
  }

  static async login({ username, password }) {
    Validaciones.username(username);
    Validaciones.password(password);

    // buscar el usuario
    const user = User.findOne({ username });
    if (!user) throw new Error("User does not exist");
    const isValid = await bcrypt.compareSync(password, user.password);
    if (!isValid) throw new Error("Invalid password");

    const { password: _, ...publicUser } = user;
    return publicUser;
  }
}

class Validaciones {
  static username(username) {
    if (typeof username !== "string") {
      throw new Error("Username must be a string");
    }
    if (username.length < 3) {
      throw new Error("Username must be at least 3 characters long");
    }
  }

  static password(password) {
    if (typeof password !== "string") {
      throw new Error("Password must be a string");
    }
    if (password.length < 6) {
      throw new Error("Password must be at least 6 characters long");
    }
  }
}
