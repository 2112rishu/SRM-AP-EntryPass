"use strict";

/* =========================================================
   SRM AP DAYPASS - COMPLETE SERVER
   ========================================================= */

require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

/* =========================================================
   FIREBASE ADMIN - MODERN SDK
   ========================================================= */

const {
    initializeApp,
    getApps,
    cert
} = require("firebase-admin/app");

const {
    getAuth
} = require("firebase-admin/auth");

const {
    getFirestore,
    FieldValue
} = require("firebase-admin/firestore");

/* =========================================================
   APP CONFIG
   ========================================================= */

const app = express();

const PORT = Number(process.env.PORT || 3000);

const QR_SECRET = process.env.DAYPASS_QR_SECRET;

const QR_TTL = 120; // QR valid for 120 seconds

const DAILY_LIMIT = 3;

/* =========================================================
   BASIC VALIDATION
   ========================================================= */

if (!QR_SECRET || QR_SECRET.length < 48) {
    console.error("");
    console.error("❌ DAYPASS_QR_SECRET is missing or too short.");
    console.error("Please add a secret of at least 48 characters to .env");
    console.error("");
    process.exit(1);
}

/* =========================================================
   FIREBASE INITIALIZATION
   ========================================================= */

function initializeFirebase() {
    try {
        /* Already initialized */
        if (getApps().length > 0) {
            console.log("✅ Firebase Admin already initialized");
            return;
        }

        let serviceAccount;

        /* -----------------------------------------------------
           OPTION 1: Environment variable
           Used mainly on Render
        ----------------------------------------------------- */

        if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
            try {
                serviceAccount = JSON.parse(
                    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
                );
            } catch (error) {
                console.error(
                    "❌ FIREBASE_SERVICE_ACCOUNT_JSON contains invalid JSON."
                );
                console.error(error.message);
                process.exit(1);
            }
        }

        /* -----------------------------------------------------
           OPTION 2: Local JSON file
        ----------------------------------------------------- */

        else {
            const serviceAccountPath = path.join(
                __dirname,
                "firebase-service-account.json"
            );

            if (!fs.existsSync(serviceAccountPath)) {
                console.error("");
                console.error(
                    "❌ firebase-service-account.json not found."
                );
                console.error(
                    "Place firebase-service-account.json inside:"
                );
                console.error(__dirname);
                console.error("");
                process.exit(1);
            }

            try {
                serviceAccount = JSON.parse(
                    fs.readFileSync(serviceAccountPath, "utf8")
                );
            } catch (error) {
                console.error(
                    "❌ Could not read firebase-service-account.json"
                );
                console.error(error.message);
                process.exit(1);
            }
        }

        /* -----------------------------------------------------
           Validate service account
        ----------------------------------------------------- */

        if (
            !serviceAccount ||
            !serviceAccount.project_id ||
            !serviceAccount.client_email ||
            !serviceAccount.private_key
        ) {
            console.error(
                "❌ Firebase service account is incomplete."
            );
            process.exit(1);
        }

        /* -----------------------------------------------------
           Initialize Firebase
        ----------------------------------------------------- */

        initializeApp({
            credential: cert(serviceAccount)
        });

        console.log("✅ Firebase Admin initialized successfully");

    } catch (error) {
        console.error("");
        console.error("❌ Firebase initialization failed");
        console.error(error);
        console.error("");
        process.exit(1);
    }
}

initializeFirebase();

/* =========================================================
   FIREBASE SERVICES
   ========================================================= */

const db = getFirestore();
const auth = getAuth();

console.log("✅ Firebase Firestore connected");
console.log("✅ Firebase Authentication connected");

/* =========================================================
   EXPRESS SECURITY
   ========================================================= */

app.disable("x-powered-by");

app.use(
    helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        referrerPolicy: {
            policy: "strict-origin-when-cross-origin"
        },
        frameguard: {
            action: "deny"
        },
        hidePoweredBy: true
    })
);

app.use(
    express.json({
        limit: "20kb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "20kb"
    })
);

/* =========================================================
   GLOBAL RATE LIMIT
   ========================================================= */

app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 300,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            error: "Too many requests. Please try again later."
        }
    })
);

/* =========================================================
   QR RATE LIMIT
   ========================================================= */

const qrLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many QR requests. Please wait a moment."
    }
});

/* =========================================================
   HELPERS
   ========================================================= */

function clean(value, length = 500) {
    if (value === undefined || value === null) {
        return "";
    }

    return String(value)
        .trim()
        .slice(0, length);
}

/* =========================================================
   INDIA DATE
   ========================================================= */

function getToday() {
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    }).format(new Date());
}

/* =========================================================
   CONSTANT TIME COMPARE
   ========================================================= */

function sameConstantTime(a, b) {
    try {
        const x = Buffer.from(a);
        const y = Buffer.from(b);

        if (x.length !== y.length) {
            return false;
        }

        return crypto.timingSafeEqual(x, y);

    } catch (_) {
        return false;
    }
}

/* =========================================================
   AUDIT LOG
   ========================================================= */

async function audit(
    actorUid,
    actorRole,
    action,
    targetUid = null,
    details = {}
) {
    try {
        await db.collection("auditLogs").add({
            actorUid,
            actorRole,
            action,
            targetUid,
            details,
            createdAt: FieldValue.serverTimestamp()
        });
    } catch (error) {
        console.error(
            "⚠️ Audit log error:",
            error.message
        );
    }
}

/* =========================================================
   AUTHENTICATION
   ========================================================= */

async function authenticate(req, res, next) {

    try {

        const header =
            req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {

            return res.status(401).json({
                success: false,
                error: "AUTH_REQUIRED",
                message: "Authentication required."
            });
        }

        const token =
            header.substring(7).trim();

        if (!token) {

            return res.status(401).json({
                success: false,
                error: "AUTH_REQUIRED",
                message: "Authentication token is missing."
            });
        }

        /* Verify Firebase token + check revocation */

        const decoded =
            await auth.verifyIdToken(token, true);

        const uid = decoded.uid;

        /* Load application profile */

        const profileSnap =
            await db
                .collection("students")
                .doc(uid)
                .get();

        if (!profileSnap.exists) {

            return res.status(403).json({
                success: false,
                error: "PROFILE_NOT_FOUND",
                message: "User profile not found."
            });
        }

        const profile =
            profileSnap.data();

        const accountStatus =
            profile.accountStatus || "ACTIVE";

        if (accountStatus !== "ACTIVE") {

            return res.status(403).json({
                success: false,
                error: "ACCOUNT_BLOCKED",
                message: "This account is blocked."
            });
        }

        req.user = {
            uid,
            email:
                decoded.email ||
                profile.email ||
                "",
            name:
                profile.name ||
                decoded.name ||
                "",
            studentId:
                profile.studentId ||
                "",
            studentType:
                profile.studentType ||
                "",
            role:
                profile.role ||
                "STUDENT",
            accountStatus
        };

        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error.message
        );

        return res.status(401).json({
            success: false,
            error: "AUTH_INVALID",
            message:
                "Your session has expired or is invalid. Please sign in again."
        });
    }
}

/* =========================================================
   ROLE CHECK
   ========================================================= */

function requireRoles(...roles) {

    return (req, res, next) => {

        if (
            !req.user ||
            !roles.includes(req.user.role)
        ) {

            return res.status(403).json({
                success: false,
                error: "NOT_AUTHORIZED",
                message:
                    "You are not authorized to perform this action."
            });
        }

        next();
    };
}

/* =========================================================
   QR SIGNATURE
   ========================================================= */

function createSignature(data) {

    return crypto
        .createHmac(
            "sha256",
            QR_SECRET
        )
        .update(data)
        .digest("base64url");
}

/* =========================================================
   CREATE QR
   ========================================================= */

function createQR(user) {

    const now =
        Math.floor(Date.now() / 1000);

    const payload = {
        v: 1,
        uid: user.uid,
        studentId: user.studentId,
        iat: now,
        exp: now + QR_TTL,
        nonce:
            crypto
                .randomBytes(16)
                .toString("hex")
    };

    const encoded =
        Buffer
            .from(JSON.stringify(payload))
            .toString("base64url");

    const signature =
        createSignature(encoded);

    return {
        token:
            `${encoded}.${signature}`,
        issuedAt: now,
        expiresAt: now + QR_TTL
    };
}

/* =========================================================
   VERIFY QR
   ========================================================= */

function verifyQR(token) {

    if (!token) {
        throw new Error(
            "QR code is required."
        );
    }

    const parts =
        token.split(".");

    if (parts.length !== 2) {
        throw new Error(
            "Invalid QR code."
        );
    }

    const encoded = parts[0];
    const signature = parts[1];

    const expected =
        createSignature(encoded);

    if (
        !sameConstantTime(
            signature,
            expected
        )
    ) {
        throw new Error(
            "Invalid QR signature."
        );
    }

    let payload;

    try {

        payload =
            JSON.parse(
                Buffer
                    .from(
                        encoded,
                        "base64url"
                    )
                    .toString("utf8")
            );

    } catch (_) {

        throw new Error(
            "Invalid QR data."
        );
    }

    const now =
        Math.floor(Date.now() / 1000);

    if (payload.v !== 1) {
        throw new Error(
            "Unsupported QR version."
        );
    }

    if (
        !payload.uid ||
        !payload.studentId ||
        !payload.nonce
    ) {
        throw new Error(
            "Incomplete QR code."
        );
    }

    if (payload.exp <= now) {
        throw new Error(
            "QR code has expired."
        );
    }

    if (payload.iat > now + 5) {
        throw new Error(
            "Invalid QR issue time."
        );
    }

    if (
        payload.exp - payload.iat >
        QR_TTL + 5
    ) {
        throw new Error(
            "Invalid QR lifetime."
        );
    }

    return payload;
}

/* =========================================================
   STATUS
   ========================================================= */

app.get("/api/status", (req, res) => {

    res.json({
        success: true,
        status: "online",
        time: new Date().toISOString()
    });
});

/* =========================================================
   CURRENT USER
   ========================================================= */

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {

        res.json({
            success: true,
            user: req.user
        });
    }
);

/* =========================================================
   STUDENT QR GENERATION
   ========================================================= */

async function generateQR(req, res) {

    try {

        if (req.user.role !== "STUDENT") {

            return res.status(403).json({
                success: false,
                error:
                    "Only students can generate QR codes."
            });
        }

        const snapshot =
            await db
                .collection("entries")
                .where(
                    "studentUid",
                    "==",
                    req.user.uid
                )
                .get();

        const today =
            getToday();

        let todayCount = 0;

        snapshot.forEach(doc => {

            const data =
                doc.data();

            if (
                data.dayKey === today
            ) {
                todayCount++;
            }
        });

        if (
            todayCount >= DAILY_LIMIT
        ) {

            return res.status(429).json({
                success: false,
                error:
                    "Daily entry limit reached.",
                dailyCount: todayCount,
                dailyLimit: DAILY_LIMIT
            });
        }

        const qr =
            createQR(req.user);

        await audit(
            req.user.uid,
            req.user.role,
            "QR_GENERATED",
            req.user.uid
        );

        res.json({
            success: true,

            qrData: qr.token,

            token: qr.token,

            issuedAt:
                qr.issuedAt,

            expiresAt:
                qr.expiresAt,

            qr: {
                token: qr.token,
                issuedAt:
                    new Date(
                        qr.issuedAt * 1000
                    ).toISOString(),
                expiresAt:
                    new Date(
                        qr.expiresAt * 1000
                    ).toISOString()
            },

            dailyCount: todayCount,

            dailyLimit:
                DAILY_LIMIT
        });

    } catch (error) {

        console.error(
            "QR generation error:",
            error
        );

        res.status(500).json({
            success: false,
            error:
                "Unable to generate QR code."
        });
    }
}

app.get(
    "/api/qr",
    qrLimiter,
    authenticate,
    generateQR
);

app.post(
    "/api/qr",
    qrLimiter,
    authenticate,
    generateQR
);

/* =========================================================
   VERIFY QR
   SECURITY + SUPER ADMIN
   ========================================================= */

app.post(
    "/api/verify-qr",
    qrLimiter,
    authenticate,
    requireRoles(
        "SECURITY",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const token =
                clean(
                    req.body.qrData ||
                    req.body.token ||
                    req.body.qr,
                    10000
                );

            const payload =
                verifyQR(token);

            /* ---------------------------------------------
               Find student
            --------------------------------------------- */

            const studentSnap =
                await db
                    .collection("students")
                    .doc(payload.uid)
                    .get();

            if (!studentSnap.exists) {

                throw new Error(
                    "Student account not found."
                );
            }

            const student =
                studentSnap.data();

            if (
                (student.accountStatus ||
                    "ACTIVE") !==
                "ACTIVE"
            ) {

                throw new Error(
                    "Student account is blocked."
                );
            }

            if (
                clean(student.studentId) !==
                clean(payload.studentId)
            ) {

                throw new Error(
                    "Student ID verification failed."
                );
            }

            const today =
                getToday();

            /* ---------------------------------------------
               Transaction
            --------------------------------------------- */

            const result =
                await db.runTransaction(
                    async transaction => {

                        /* Replay protection */

                        const nonceRef =
                            db
                                .collection(
                                    "usedQRNonces"
                                )
                                .doc(
                                    payload.nonce
                                );

                        const nonceSnap =
                            await transaction.get(
                                nonceRef
                            );

                        if (
                            nonceSnap.exists
                        ) {

                            throw new Error(
                                "This QR code has already been used."
                            );
                        }

                        /* Count today's entries */

                        const entriesSnap =
                            await db
                                .collection(
                                    "entries"
                                )
                                .where(
                                    "studentUid",
                                    "==",
                                    payload.uid
                                )
                                .get();

                        let todayCount = 0;

                        entriesSnap.forEach(
                            doc => {

                                const data =
                                    doc.data();

                                if (
                                    data.dayKey ===
                                    today
                                ) {
                                    todayCount++;
                                }
                            }
                        );

                        if (
                            todayCount >=
                            DAILY_LIMIT
                        ) {

                            throw new Error(
                                "Student has reached the daily entry limit."
                            );
                        }

                        const entryRef =
                            db
                                .collection(
                                    "entries"
                                )
                                .doc();

                        const newCount =
                            todayCount + 1;

                        const entryData = {

                            studentUid:
                                payload.uid,

                            studentId:
                                student.studentId,

                            studentName:
                                student.name ||
                                "",

                            studentEmail:
                                student.email ||
                                "",

                            studentType:
                                student.studentType ||
                                "",

                            verifierUid:
                                req.user.uid,

                            verifierName:
                                req.user.name ||
                                "",

                            verifierRole:
                                req.user.role,

                            verifiedBy:
                                req.user.name ||
                                req.user.uid,

                            verifiedByRole:
                                req.user.role,

                            dayKey:
                                today,

                            status:
                                "ALLOWED",

                            qrNonce:
                                payload.nonce,

                            createdAt:
                                FieldValue.serverTimestamp()
                        };

                        transaction.set(
                            entryRef,
                            entryData
                        );

                        transaction.set(
                            nonceRef,
                            {
                                studentUid:
                                    payload.uid,

                                usedBy:
                                    req.user.uid,

                                usedByRole:
                                    req.user.role,

                                usedAt:
                                    FieldValue.serverTimestamp()
                            }
                        );

                        return {
                            entryId:
                                entryRef.id,

                            dailyCount:
                                newCount,

                            dailyLimit:
                                DAILY_LIMIT,

                            remainingEntries:
                                DAILY_LIMIT -
                                newCount
                        };
                    }
                );

            /* ---------------------------------------------
               Audit
            --------------------------------------------- */

            await audit(
                req.user.uid,
                req.user.role,
                "ENTRY_ALLOWED",
                payload.uid,
                {
                    studentId:
                        student.studentId,

                    entryId:
                        result.entryId
                }
            );

            /* ---------------------------------------------
               SUCCESS
            --------------------------------------------- */

            return res.json({

                success: true,

                status:
                    "ALLOWED",

                message:
                    "Entry allowed.",

                student: {

                    uid:
                        payload.uid,

                    studentId:
                        student.studentId,

                    name:
                        student.name ||
                        "",

                    email:
                        student.email ||
                        "",

                    studentType:
                        student.studentType ||
                        ""
                },

                entry: {

                    entryId:
                        result.entryId,

                    dailyCount:
                        result.dailyCount,

                    dailyLimit:
                        result.dailyLimit,

                    remainingEntries:
                        result.remainingEntries,

                    verifiedBy:
                        req.user.name ||
                        req.user.uid,

                    verifiedByRole:
                        req.user.role
                },

                entryId:
                    result.entryId,

                dailyCount:
                    result.dailyCount,

                dailyLimit:
                    result.dailyLimit,

                remainingEntries:
                    result.remainingEntries,

                verifiedBy:
                    req.user.name ||
                    req.user.uid,

                verifiedByRole:
                    req.user.role
            });

        } catch (error) {

            console.error(
                "QR verification error:",
                error.message
            );

            return res.status(400).json({

                success: false,

                status:
                    "REJECTED",

                error:
                    error.message ||
                    "QR verification failed."
            });
        }
    }
);

/* =========================================================
   STUDENT / STAFF ENTRIES
   ========================================================= */

app.get(
    "/api/entries/:studentId",
    authenticate,
    async (req, res) => {

        try {

            const requestedId =
                clean(
                    req.params.studentId,
                    100
                );

            if (
                req.user.role ===
                "STUDENT" &&
                req.user.studentId !==
                requestedId
            ) {

                return res.status(403).json({
                    success: false,
                    error:
                        "Students can only view their own entries."
                });
            }

            let query =
                db
                    .collection("entries")
                    .where(
                        "studentId",
                        "==",
                        requestedId
                    );

            const snapshot =
                await query.get();

            const entries =
                snapshot.docs
                    .map(doc => ({
                        id: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt.toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt.toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return bTime - aTime;
                        }
                    );

            res.json({
                success: true,
                entries
            });

        } catch (error) {

            console.error(
                "Entries error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load entries."
            });
        }
    }
);

/* =========================================================
   ADMIN / SECURITY ALL ENTRIES
   ========================================================= */

app.get(
    "/api/admin/entries",
    authenticate,
    requireRoles(
        "SECURITY",
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .collection("entries")
                    .limit(500)
                    .get();

            const staffSnapshot =
                await db
                    .collection("students")
                    .get();

            const staffMap =
                new Map();

            staffSnapshot.forEach(
                doc => {

                    const data =
                        doc.data();

                    staffMap.set(
                        doc.id,
                        data
                    );
                }
            );

            const entries =
                snapshot.docs
                    .map(doc => {

                        const data =
                            doc.data();

                        const verifier =
                            staffMap.get(
                                data.verifierUid
                            );

                        return {

                            id:
                                doc.id,

                            ...data,

                            verifierName:
                                data.verifierName ||
                                verifier?.name ||
                                data.verifiedBy ||
                                data.verifierUid ||
                                "",

                            verifierRole:
                                data.verifierRole ||
                                verifier?.role ||
                                data.verifiedByRole ||
                                ""
                        };
                    })
                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt.toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt.toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return bTime - aTime;
                        }
                    );

            res.json({
                success: true,
                entries
            });

        } catch (error) {

            console.error(
                "Admin entries error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load entries."
            });
        }
    }
);

/* =========================================================
   ID GENERATOR
   ========================================================= */

async function generateNextId(prefix) {

    const counterRef =
        db
            .collection("idCounters")
            .doc(prefix);

    const result =
        await db.runTransaction(
            async transaction => {

                const snap =
                    await transaction.get(
                        counterRef
                    );

                let nextNumber = 1;

                if (snap.exists) {

                    const data =
                        snap.data();

                    nextNumber =
                        Number(
                            data.lastNumber || 0
                        ) + 1;
                }

                transaction.set(
                    counterRef,
                    {
                        lastNumber:
                            nextNumber,

                        updatedAt:
                            FieldValue.serverTimestamp()
                    },
                    {
                        merge: true
                    }
                );

                return nextNumber;
            }
        );

    return `${prefix}-${String(result).padStart(4, "0")}`;
}

/* =========================================================
   SUPER ADMIN CREATE USER
   ========================================================= */

app.post(
    "/api/super-admin/create-user",
    authenticate,
    requireRoles("SUPER_ADMIN"),
    async (req, res) => {

        try {

            const email =
                clean(
                    req.body.email,
                    200
                );

            const password =
                String(
                    req.body.password || ""
                );

            const name =
                clean(
                    req.body.name,
                    200
                );

            const role =
                clean(
                    req.body.role,
                    50
                ).toUpperCase();

            const studentType =
                clean(
                    req.body.studentType,
                    100
                );

            const allowedRoles = [
                "STUDENT",
                "SECURITY",
                "ADMIN",
                "SUPER_ADMIN"
            ];

            if (
                !allowedRoles.includes(role)
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid user role."
                });
            }

            if (
                !email ||
                !name ||
                password.length < 8
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Valid name, email and password are required. Password must contain at least 8 characters."
                });
            }

            let prefix;

            if (role === "STUDENT") {
                prefix = "SRMAP-STU";
            }

            else if (
                role === "SECURITY"
            ) {
                prefix = "SRMAP-SEC";
            }

            else if (
                role === "ADMIN"
            ) {
                prefix = "SRMAP-ADM";
            }

            else {
                prefix = "SRMAP-SADM";
            }

            const generatedId =
                await generateNextId(
                    prefix
                );

            const user =
                await auth.createUser({
                    email,
                    password,
                    displayName:
                        name
                });

            try {

                await db
                    .collection("students")
                    .doc(user.uid)
                    .set({

                        uid:
                            user.uid,

                        email,

                        name,

                        studentId:
                            generatedId,

                        studentType:
                            role === "STUDENT"
                                ? studentType
                                : "STAFF",

                        role,

                        accountStatus:
                            "ACTIVE",

                        createdAt:
                            FieldValue.serverTimestamp()
                    });

            } catch (firestoreError) {

                await auth.deleteUser(
                    user.uid
                );

                throw firestoreError;
            }

            await audit(
                req.user.uid,
                req.user.role,
                "USER_CREATED",
                user.uid,
                {
                    role,
                    studentId:
                        generatedId,
                    email
                }
            );

            res.status(201).json({

                success: true,

                message:
                    `${role} account created successfully.`,

                user: {

                    uid:
                        user.uid,

                    name,

                    email,

                    role,

                    studentId:
                        generatedId,

                    accountStatus:
                        "ACTIVE"
                }
            });

        } catch (error) {

            console.error(
                "Super Admin create user error:",
                error
            );

            if (
                error.code ===
                "auth/email-already-exists"
            ) {

                return res.status(409).json({
                    success: false,
                    error:
                        "An account with this email already exists."
                });
            }

            res.status(500).json({
                success: false,
                error:
                    error.message ||
                    "Unable to create user."
            });
        }
    }
);

/* =========================================================
   CREATE STUDENT
   ========================================================= */

app.post(
    "/api/students",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const email =
                clean(
                    req.body.email,
                    200
                );

            const password =
                String(
                    req.body.password || ""
                );

            const name =
                clean(
                    req.body.name,
                    200
                );

            const studentType =
                clean(
                    req.body.studentType,
                    100
                );

            if (
                !email ||
                !name ||
                password.length < 8
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Valid email, password and name are required."
                });
            }

            const studentId =
                await generateNextId(
                    "SRMAP-STU"
                );

            const user =
                await auth.createUser({
                    email,
                    password,
                    displayName:
                        name
                });

            try {

                await db
                    .collection("students")
                    .doc(user.uid)
                    .set({

                        uid:
                            user.uid,

                        email,

                        studentId,

                        name,

                        studentType,

                        role:
                            "STUDENT",

                        accountStatus:
                            "ACTIVE",

                        createdAt:
                            FieldValue.serverTimestamp()
                    });

            } catch (firestoreError) {

                await auth.deleteUser(
                    user.uid
                );

                throw firestoreError;
            }

            await audit(
                req.user.uid,
                req.user.role,
                "STUDENT_CREATED",
                user.uid,
                {
                    studentId
                }
            );

            res.json({

                success: true,

                message:
                    "Student created successfully.",

                uid:
                    user.uid,

                studentId
            });

        } catch (error) {

            console.error(
                "Create student error:",
                error
            );

            res.status(400).json({
                success: false,
                error:
                    error.message ||
                    "Could not create student."
            });
        }
    }
);

/* =========================================================
   CREATE STAFF
   ========================================================= */

app.post(
    "/api/admins",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const email =
                clean(
                    req.body.email,
                    200
                );

            const password =
                String(
                    req.body.password || ""
                );

            const name =
                clean(
                    req.body.name,
                    200
                );

            const role =
                clean(
                    req.body.role,
                    50
                ).toUpperCase();

            if (
                ![
                    "SECURITY",
                    "ADMIN",
                    "SUPER_ADMIN"
                ].includes(role)
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid staff role."
                });
            }

            if (
                req.user.role !==
                "SUPER_ADMIN" &&
                role === "SUPER_ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    error:
                        "Only SUPER_ADMIN can create SUPER_ADMIN accounts."
                });
            }

            if (
                !email ||
                !name ||
                password.length < 8
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Valid name, email and password are required."
                });
            }

            const prefix =
                role === "SECURITY"
                    ? "SRMAP-SEC"
                    : role === "ADMIN"
                        ? "SRMAP-ADM"
                        : "SRMAP-SADM";

            const staffId =
                await generateNextId(
                    prefix
                );

            const user =
                await auth.createUser({
                    email,
                    password,
                    displayName:
                        name
                });

            try {

                await db
                    .collection("students")
                    .doc(user.uid)
                    .set({

                        uid:
                            user.uid,

                        email,

                        name,

                        studentId:
                            staffId,

                        studentType:
                            "STAFF",

                        role,

                        accountStatus:
                            "ACTIVE",

                        createdAt:
                            FieldValue.serverTimestamp()
                    });

            } catch (firestoreError) {

                await auth.deleteUser(
                    user.uid
                );

                throw firestoreError;
            }

            await audit(
                req.user.uid,
                req.user.role,
                "STAFF_CREATED",
                user.uid,
                {
                    role,
                    studentId:
                        staffId
                }
            );

            res.json({

                success: true,

                message:
                    "Staff account created.",

                uid:
                    user.uid,

                studentId:
                    staffId,

                role
            });

        } catch (error) {

            console.error(
                "Create staff error:",
                error
            );

            res.status(400).json({
                success: false,
                error:
                    error.message ||
                    "Could not create staff."
            });
        }
    }
);

/* =========================================================
   ALL USERS
   ========================================================= */

app.get(
    "/api/admin/users",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .collection("students")
                    .get();

            const users =
                snapshot.docs
                    .map(doc => ({
                        uid: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) =>
                            String(
                                a.name || ""
                            ).localeCompare(
                                String(
                                    b.name || ""
                                )
                            )
                    );

            res.json({
                success: true,
                users
            });

        } catch (error) {

            console.error(
                "Users list error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load users."
            });
        }
    }
);

/* =========================================================
   STUDENTS LIST
   ========================================================= */

app.get(
    "/api/students",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .collection("students")
                    .where(
                        "role",
                        "==",
                        "STUDENT"
                    )
                    .get();

            const students =
                snapshot.docs.map(
                    doc => ({
                        uid: doc.id,
                        ...doc.data()
                    })
                );

            res.json({
                success: true,
                students
            });

        } catch (error) {

            console.error(
                "Students list error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load students."
            });
        }
    }
);

/* =========================================================
   STAFF LIST
   ========================================================= */

app.get(
    "/api/admin/staff",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .collection("students")
                    .where(
                        "role",
                        "in",
                        [
                            "SECURITY",
                            "ADMIN",
                            "SUPER_ADMIN"
                        ]
                    )
                    .get();

            const staff =
                snapshot.docs.map(
                    doc => ({
                        uid: doc.id,
                        ...doc.data()
                    })
                );

            res.json({
                success: true,
                staff
            });

        } catch (error) {

            console.error(
                "Staff list error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load staff."
            });
        }
    }
);

/* =========================================================
   BLOCK / ACTIVATE USER
   ========================================================= */

app.post(
    "/api/users/:uid/status",
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (req, res) => {

        try {

            const uid =
                clean(
                    req.params.uid,
                    200
                );

            const status =
                clean(
                    req.body.status,
                    50
                ).toUpperCase();

            if (
                uid === req.user.uid
            ) {

                return res.status(403).json({
                    success: false,
                    error:
                        "You cannot change your own account status."
                });
            }

            if (
                ![
                    "ACTIVE",
                    "BLOCKED"
                ].includes(status)
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid account status."
                });
            }

            const ref =
                db
                    .collection("students")
                    .doc(uid);

            const snap =
                await ref.get();

            if (!snap.exists) {

                return res.status(404).json({
                    success: false,
                    error:
                        "User not found."
                });
            }

            const target =
                snap.data();

            if (
                target.role ===
                "SUPER_ADMIN" &&
                req.user.role !==
                "SUPER_ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    error:
                        "Only SUPER_ADMIN can modify SUPER_ADMIN."
                });
            }

            await ref.update({

                accountStatus:
                    status,

                updatedAt:
                    FieldValue.serverTimestamp()
            });

            await auth.updateUser(
                uid,
                {
                    disabled:
                        status === "BLOCKED"
                }
            );

            await audit(
                req.user.uid,
                req.user.role,
                status === "BLOCKED"
                    ? "USER_BLOCKED"
                    : "USER_UNBLOCKED",
                uid
            );

            res.json({

                success: true,

                message:
                    status === "BLOCKED"
                        ? "User blocked."
                        : "User activated."
            });

        } catch (error) {

            console.error(
                "Status update error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to update account status."
            });
        }
    }
);

/* =========================================================
   AUDIT LOGS
   ========================================================= */

app.get(
    "/api/admin/audit-logs",
    authenticate,
    requireRoles(
    "SUPER_ADMIN"
),
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .collection("auditLogs")
                    .limit(100)
                    .get();

            const logs =
                snapshot.docs
                    .map(doc => ({
                        id: doc.id,
                        ...doc.data()
                    }))
                    .sort(
                        (a, b) => {

                            const aTime =
                                a.createdAt &&
                                typeof a.createdAt.toMillis ===
                                    "function"
                                    ? a.createdAt.toMillis()
                                    : 0;

                            const bTime =
                                b.createdAt &&
                                typeof b.createdAt.toMillis ===
                                    "function"
                                    ? b.createdAt.toMillis()
                                    : 0;

                            return bTime - aTime;
                        }
                    );

            res.json({
                success: true,
                logs
            });

        } catch (error) {

            console.error(
                "Audit logs error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Unable to load audit logs."
            });
        }
    }
);

/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
    "/api/logout",
    authenticate,
    async (req, res) => {

        await audit(
            req.user.uid,
            req.user.role,
            "LOGOUT"
        );

        res.json({
            success: true
        });
    }
);

/* =========================================================
   STATIC WEBSITE
   ========================================================= */

app.use(
    express.static(
        require("path").join(__dirname, "public"),
        {
            extensions: ["html"],
            dotfiles: "deny"
        }
    )
);
/* =========================================================
   API 404
   ========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({
            success: false,
            error:
                "API endpoint not found."
        });
    }
);

/* =========================================================
   GLOBAL ERROR HANDLER
   ========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Global error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({
            success: false,
            error:
                "Internal server error."
        });
    }
);

/* =========================================================
   START SERVER
   ========================================================= */

const server =
    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log("");
            console.log(
                "========================================"
            );
            console.log(
                "       SRM AP DAYPASS SERVER"
            );
            console.log(
                "========================================"
            );
            console.log(
                `✅ Server running on port ${PORT}`
            );
            console.log(
                `🌐 http://localhost:${PORT}`
            );
            console.log(
                "🔥 Firebase Admin connected"
            );
            console.log(
                "🎫 Student QR enabled"
            );
            console.log(
                "🛡️ Security QR verification enabled"
            );
            console.log(
                "👑 Super Admin enabled"
            );
            console.log(
                "📋 Entry history enabled"
            );
            console.log(
                "🔐 Audit logging enabled"
            );
            console.log(
                "========================================"
            );
            console.log("");
        }
    );

/* =========================================================
   SERVER ERROR
   ========================================================= */

server.on(
    "error",
    error => {

        console.error(
            "❌ Server error:",
            error
        );

        if (
            error.code ===
            "EADDRINUSE"
        ) {

            console.error(
                `Port ${PORT} is already in use.`
            );
        }

        process.exit(1);
    }
);

/* =========================================================
   SHUTDOWN
   ========================================================= */

process.on(
    "SIGINT",
    () => {

        console.log(
            "\nShutting down server..."
        );

        server.close(
            () => process.exit(0)
        );
    }
);

process.on(
    "SIGTERM",
    () => {

        server.close(
            () => process.exit(0)
        );
    }
);