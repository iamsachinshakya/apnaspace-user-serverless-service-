import { Request, Response, NextFunction } from "express";
import { ApiError } from "../../common/utils/apiError";
import { ErrorCode } from "../../common/constants/errorCodes";
import { UserRole } from "../../auth/models/auth.entity";
import { IAuthUser } from "../../auth/models/auth.dto";

/**
 * Authorization middleware
 *
 * Rules:
 * - User:
 *   - CAN act on self
 *   - CANNOT act on others
 * - Admin:
 *   - CAN act on others
 *   - CANNOT DELETE self
 */
export const authorizeUserAction =
    (message = "Action not allowed on yourself") =>
        (req: Request, _res: Response, next: NextFunction): void => {
            const user = req.user as IAuthUser | undefined;
            const targetUserId = req.params?.id;
            const method = req.method?.toUpperCase();

            /* ---------- AUTH CHECK ---------- */
            if (!user) {
                throw new ApiError(
                    "Unauthorized request",
                    401,
                    ErrorCode.UNAUTHORIZED
                );
            }

            /* ---------- INPUT VALIDATION ---------- */
            if (!targetUserId || typeof targetUserId !== "string") {
                throw new ApiError(
                    "Target user not specified",
                    400,
                    ErrorCode.BAD_REQUEST
                );
            }

            const isSelf = user.id === targetUserId;
            const isAdmin = user.role === UserRole.ADMIN;

            /* ---------- ADMIN RULES ---------- */
            if (isAdmin) {
                // Admin cannot delete itself
                if (isSelf && method === "DELETE") {
                    throw new ApiError(
                        message,
                        403,
                        ErrorCode.PERMISSION_DENIED
                    );
                }

                // Admin allowed for all other cases
                return next();
            }

            /* ---------- USER RULES ---------- */
            if (isSelf) {
                // User can act on own resource
                return next();
            }

            /* ---------- FALLBACK ---------- */
            throw new ApiError(
                "You do not have permission to perform this action",
                403,
                ErrorCode.PERMISSION_DENIED
            );
        };
