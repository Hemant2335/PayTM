import db from "@repo/db/client";
import bcrypt from "bcrypt";
import CredentialsProvider from "next-auth/providers/credentials";

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        phone: {
          label: "Phone number",
          type: "text",
          placeholder: "+91xxxxx12345",
        },
        password: { label: "Password", type: "password" },
      },

      // Write your authorize algo
      async authorize(credentials: any) {
        const hashedpass = await bcrypt.hash(credentials.password, 10);
        const existingUser = await db.user.findFirst({
          where: {
            number: credentials.phone,
          },
        });

        if (existingUser) {
          const passvalidate = await bcrypt.compare(
            credentials.password,
            existingUser.password
          );
          if (passvalidate) {
            return {
              id: existingUser.id.toString(),
              name: existingUser.name,
              email: existingUser.email,
              number: existingUser.number,
            };
          }
          return null;
        }

        try {
          const user = await db.user.create({
            data: {
              number: credentials.phone,
              password: hashedpass,
            },
          });
          return {
            id: user.id.toString(),
            name: user.name,
            email: user.email,
            number: user.number,
          };
        } catch (error) {
          console.log(error);
        }
        return null;
      },
    }),
  ],
  secret: process.env.JWT_SECRET || "secret",
  callbacks: {
    async session({ token, session }: any) {
      console.log(token , session);
      session.user.id = token.sub;
      return session;
    },
  },
};
