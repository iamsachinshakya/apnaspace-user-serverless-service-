import User from "../models/user.model";
import { IUserRepository } from "./user.repository.interface";
import { IUserEntity } from "../models/user.entity";
import {
    IFollowCount,
    IFollowUser,
    IUpdateUser,
    IUserDashboard,
} from "../models/user.dto";
import { IQueryParams, PaginatedData } from "../../common/models/common.dto";
import logger from "../../../../app/utils/logger";
import mongoose from "mongoose";

export class UserRepository implements IUserRepository {

    private normalizeUser(u: any): IUserDashboard {
        return {
            id: u._id.toString(),
            fullName: u.fullName,
            avatar: u.avatar ?? null,
            bio: u.bio ?? "",
            socialLinks: u.socialLinks ?? {
                twitter: null,
                linkedin: null,
                github: null,
                website: null,
            },
            preferences: u.preferences ?? {
                emailNotifications: true,
                marketingUpdates: false,
                twoFactorAuth: false,
            },
            createdAt: u.createdAt,
            updatedAt: u.updatedAt,
        };
    }

    // ---------------- CREATE ----------------
    async create(data: IUserEntity): Promise<IUserDashboard | null> {
        try {
            const user = await User.create(data);
            return this.normalizeUser(user);
        } catch (error) {
            logger.error("Error creating user: %o", error);
            return null;
        }
    }

    // ---------------- FIND ALL (PAGINATED) ----------------
    async findAll(params: IQueryParams): Promise<PaginatedData<IUserDashboard>> {
        try {
            const {
                page = 1,
                limit = 10,
                search = "",
                sortBy = "createdAt",
                sortOrder = "desc",
            } = params;

            const skip = (page - 1) * limit;

            const filter: any = {};
            if (search.trim()) {
                filter.fullName = { $regex: search, $options: "i" };
            }

            const sort: any = {
                [sortBy === "fullName" ? "fullName" : "createdAt"]:
                    sortOrder === "asc" ? 1 : -1,
            };

            const [users, total] = await Promise.all([
                User.find(filter)
                    .sort(sort)
                    .skip(skip)
                    .limit(limit)
                    .select("fullName avatar bio socialLinks preferences createdAt updatedAt")
                    .lean(),
                User.countDocuments(filter),
            ]);

            return {
                data: users.map(this.normalizeUser),
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                },
            };
        } catch (error) {
            logger.error("Error fetching users: %o", error);
            return {
                data: [],
                pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
            };
        }
    }

    // ---------------- FIND BY ID ----------------
    async findById(id: string): Promise<IUserDashboard | null> {
        try {
            if (!mongoose.Types.ObjectId.isValid(id)) return null;

            const user = await User.findById(id)
                .select("fullName avatar bio socialLinks preferences createdAt updatedAt")
                .lean();

            return user ? this.normalizeUser(user) : null;
        } catch (error) {
            logger.error("Error finding user by id %s: %o", id, error);
            return null;
        }
    }

    // ---------------- UPDATE ----------------
    async updateAccountById(
        userId: string,
        updates: Partial<IUpdateUser>
    ): Promise<Partial<IUpdateUser> | null> {
        try {
            const result = await User.findByIdAndUpdate(
                userId,
                { $set: updates },
                { new: true }
            );
            return result ? updates : null;
        } catch (error) {
            logger.error("Error updating user %s: %o", userId, error);
            return null;
        }
    }

    // ---------------- DELETE ----------------
    async deleteById(userId: string): Promise<boolean> {
        try {
            const result = await User.findByIdAndDelete(userId);
            return !!result;
        } catch (error) {
            logger.error("Error deleting user %s: %o", userId, error);
            return false;
        }
    }

    // ---------------- FOLLOW LOGIC ----------------
    async followUser(
        userId: string,
        targetUserId: string
    ): Promise<boolean> {
        const session = await User.startSession();
        session.startTransaction();

        try {
            // Add userId to targetUserId.followers
            await User.findByIdAndUpdate(
                targetUserId,
                { $addToSet: { followers: userId } },
                { session }
            );

            // Add targetUserId to userId.following
            await User.findByIdAndUpdate(
                userId,
                { $addToSet: { following: targetUserId } },
                { session }
            );

            await session.commitTransaction();
            session.endSession();
            return true;
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            logger.error(
                "Error following user %s by %s: %o",
                targetUserId,
                userId,
                error
            );
            return false;
        }
    }

    async removeFollow(
        userId: string,
        targetUserId: string
    ): Promise<boolean> {
        if (userId === targetUserId) return false;

        const session = await User.startSession();
        session.startTransaction();

        try {
            // Remove userId from targetUserId.followers
            await User.findByIdAndUpdate(
                targetUserId,
                { $pull: { followers: userId } },
                { session }
            );

            // Remove targetUserId from userId.following
            await User.findByIdAndUpdate(
                userId,
                { $pull: { following: targetUserId } },
                { session }
            );

            await session.commitTransaction();
            session.endSession();
            return true;
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            logger.error(
                "Error removing follow relationship between %s and %s: %o",
                userId,
                targetUserId,
                error
            );
            return false;
        }
    }


    // ---------------- FOLLOWERS / FOLLOWING ----------------
    async findFollowers(userId: string): Promise<IFollowUser[]> {
        try {
            const user = await User.findById(userId)
                .select("followers")
                .lean();

            if (!user || user.followers.length === 0) return [];

            const followers = await User.find({
                _id: { $in: user.followers },
            })
                .select("fullName avatar")
                .lean();

            return followers.map((u: any) => ({
                id: u._id.toString(),
                fullName: u.fullName,
                avatar: u.avatar ?? null,
            }));
        } catch (error) {
            logger.error("Error fetching followers for user %s: %o", userId, error);
            return [];
        }
    }


    async findFollowing(userId: string): Promise<IFollowUser[]> {
        try {
            const user = await User.findById(userId)
                .select("following")
                .lean();

            if (!user || user.following.length === 0) return [];

            const followingUsers = await User.find({
                _id: { $in: user.following },
            })
                .select("fullName avatar")
                .lean();

            return followingUsers.map((u: any) => ({
                id: u._id.toString(),
                fullName: u.fullName,
                avatar: u.avatar ?? null,
            }));
        } catch (error) {
            logger.error("Error fetching following for user %s: %o", userId, error);
            return [];
        }
    }


    // ---------------- IS FOLLOWING ----------------
    async isFollowing(userId: string, targetUserId: string): Promise<boolean> {
        try {
            const user = await User.findOne({
                _id: targetUserId,
                followers: userId,
            }).lean();

            return !!user;
        } catch (error) {
            logger.error(
                "Error checking if user %s is following %s: %o",
                userId,
                targetUserId,
                error
            );
            return false;
        }
    }

    // ---------------- FOLLOW COUNTS ----------------
    async getFollowCounts(userId: string): Promise<IFollowCount | null> {
        try {
            const user = await User.findById(userId)
                .select("followers following")
                .lean();

            if (!user) return null;

            return {
                followerCount: user.followers?.length ?? 0,
                followingCount: user.following?.length ?? 0,
            };
        } catch (error) {
            logger.error(
                "Error fetching follow counts for user %s: %o",
                userId,
                error
            );
            return null;
        }
    }
}
