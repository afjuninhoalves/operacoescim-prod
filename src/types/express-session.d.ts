// src/types/express-session.d.ts
import 'express-session';

declare module 'express-session' {
  interface SessionData {
    user?: {
      id: number;
      nome?: string;
      email?: string;
      role?: string;
      [k: string]: any;
    };
  }
}
