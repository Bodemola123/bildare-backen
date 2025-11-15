// types/express-session.d.ts
import "express-session";

declare module "express-session" {
  interface SessionData {
    user?: {
      id: number;
      email: string;
      username?: string;
      role?: string;
      region?: string;
      interests?: any;
      accessToken: string;
      refreshToken: string;
    };
  }
}
