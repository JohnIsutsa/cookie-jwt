import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-jwt";

class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                JwtStrategy.extractJWT,
                ExtractJWT.fromAuthHeaderAsBearerToken(),
            ]),
            ignoreExpiration: false,
            secretOrKey: 'secret',
        });
    }

    private static extractJWT(req: RequestType): string | null {
        if(
            req.cookies &&
            'user_token' in req.cookies &&
            req.cookies.user_token.length > 0
        ) {
            return req.cookies.user_token;
        }
    }

    async validate(payload: any) {
        return { userId: payload.sub, username: payload.username };
    }
}