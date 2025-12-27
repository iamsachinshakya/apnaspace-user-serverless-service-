import app from "./app/app";
import { Environment } from "./app/config/constants";
import { env } from "./app/config/env";
import { connectDB } from "./app/db/mongodb/connectDB";
import logger from "./app/utils/logger";

let initPromise: Promise<void> | null = null;

/**
 * Initialize DB + shared resources (runs once in serverless)
 */
async function init() {
    if (!initPromise) {
        initPromise = (async () => {
            await connectDB();
            logger.info("🚀 App initialized");
        })();
    }
    await initPromise;
}

/**
 * SERVERLESS HANDLER (prod)
 */
export default async function handler(req: any, res: any) {
    try {
        await init();
        return app(req, res);
    } catch (err: any) {
        logger.error("❌ Serverless handler error", err);
        res.status(500).json({ message: "Internal Server Error" });
    }
}

/**
 * LOCAL DEV SERVER
 */
if (env.NODE_ENV === Environment.DEVELOPMENT) {

    (async () => {
        try {
            await connectDB();

            app.listen(env.PORT, () => {
                logger.info(`🔥 Local server running on http://localhost:${env.PORT}`);
            });
        } catch (err) {
            logger.error("❌ Failed to start local server", err);
            process.exit(1);
        }
    })();
}
