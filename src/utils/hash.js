import bcrypt from "bcrypt";

const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);

const normalize = (h = "") => {
  if (!h) return h;
  return h.replace("$2y$", "$2b$").replace("$2a$", "$2b$");
};

export const hashPassword = async (plainPassword) => {
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
};

export const comparePassword = async (plainPassword, hash) => {
  return bcrypt.compare(plainPassword, normalize(hash));
};
