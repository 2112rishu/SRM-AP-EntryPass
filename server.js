"use strict";

/*
============================================================
 SRM AP DAYPASS - SECURE / CONCURRENT SERVER
============================================================
*/

require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

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


/*
============================================================
 CONFIGURATION
============================================================
*/

const app = express();

const PORT =
    Number(process.env.PORT || 3000);

const QR_SECRET =
    process.env.DAYPASS_QR_SECRET;

const QR_TTL = 30;

const DAILY_LIMIT = 3;

const MAX_BODY_SIZE = "20kb";

const PUBLIC_DIR =
    path.join(__dirname, "public");


/*
============================================================
 VALIDATE CONFIG
============================================================
*/

if (
    !QR_SECRET ||
    QR_SECRET.length < 48
) {
    console.error(
        "DAYPASS_QR_SECRET is missing or shorter than 48 characters."
    );

    process.exit(1);
}


/*
============================================================
 FIREBASE INITIALIZATION
============================================================
*/

function initializeFirebase() {

    if (getApps().length > 0) {
        return;
    }

    let serviceAccount;

    /*
    --------------------------------------------------------
     Render / Production
    --------------------------------------------------------
    */

    if (
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    ) {

        try {

            serviceAccount =
                JSON.parse(
                    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
                );

        } catch (error) {

            console.error(
                "Invalid FIREBASE_SERVICE_ACCOUNT_JSON."
            );

            process.exit(1);
        }

    }

    /*
    --------------------------------------------------------
     Local development
    --------------------------------------------------------
    */

    else {

        const serviceAccountFile =
            path.join(
                __dirname,
                "firebase-service-account.json"
            );

        if (
            !fs.existsSync(
                serviceAccountFile
            )
        ) {

            console.error(
                "firebase-service-account.json not found."
            );

            process.exit(1);
        }

        try {

            serviceAccount =
                JSON.parse(
                    fs.readFileSync(
                        serviceAccountFile,
                        "utf8"
                    )
                );

        } catch (error) {

            console.error(
                "Unable to read Firebase service account."
            );

            process.exit(1);
        }
    }


    initializeApp({
        credential:
            cert(serviceAccount)
    });
}


initializeFirebase();


const db =
    getFirestore();

const auth =
    getAuth();


console.log(
    "Firebase Admin initialized successfully."
);


/*
============================================================
 EXPRESS SECURITY
============================================================
*/

app.disable("x-powered-by");


app.set(
    "trust proxy",
    1
);


/*
------------------------------------------------------------
 Helmet
------------------------------------------------------------
*/

app.use(
    helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false
    })
);


/*
------------------------------------------------------------
 Request size limits
------------------------------------------------------------
*/

app.use(
    express.json({
        limit: MAX_BODY_SIZE
    })
);


app.use(
    express.urlencoded({
        extended: false,
        limit: MAX_BODY_SIZE
    })
);


/*
============================================================
 RATE LIMITERS
============================================================
*/

const globalLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max: 500,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            error:
                "Too many requests. Please try again later."
        },

        skip: req =>
            req.path === "/api/status"
    });


const authLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max: 100,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            error:
                "Too many authentication requests."
        }
    });


const qrLimiter =
    rateLimit({

        windowMs:
            60 * 1000,

        max: 30,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            error:
                "Too many QR requests. Please wait."
        }
    });


const adminLimiter =
    rateLimit({

        windowMs:
            60 * 1000,

        max: 60,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            error:
                "Too many administrative requests."
        }
    });


app.use(
    globalLimiter
);


/*
============================================================
 HELPERS
============================================================
*/

function clean(
    value,
    length = 500
) {

    if (
        value === undefined ||
        value === null
    ) {
        return "";
    }

    return String(value)
        .trim()
        .slice(0, length);
}


function getToday() {

    return new Intl.DateTimeFormat(
        "en-CA",
        {
            timeZone:
                "Asia/Kolkata",

            year: "numeric",

            month: "2-digit",

            day: "2-digit"
        }
    ).format(
        new Date()
    );
}


function sameConstantTime(
    a,
    b
) {

    try {

        const x =
            Buffer.from(
                String(a)
            );

        const y =
            Buffer.from(
                String(b)
            );

        if (
            x.length !== y.length
        ) {
            return false;
        }

        return crypto.timingSafeEqual(
            x,
            y
        );

    } catch (_) {

        return false;
    }
}


function safeDate(
    value
) {

    try {

        if (
            value &&
            typeof value.toDate ===
                "function"
        ) {
            return value.toDate();
        }

        if (
            value &&
            typeof value.toMillis ===
                "function"
        ) {
            return new Date(
                value.toMillis()
            );
        }

        if (
            value instanceof Date
        ) {
            return value;
        }

        return null;

    } catch (_) {

        return null;
    }
}


/*
============================================================
 AUDIT LOG
============================================================
*/

async function audit(
    actorUid,
    actorRole,
    action,
    targetUid = null,
    details = {}
) {

    try {

        await db
            .collection("auditLogs")
            .add({

                actorUid:
                    clean(
                        actorUid,
                        200
                    ),

                actorRole:
                    clean(
                        actorRole,
                        50
                    ),

                action:
                    clean(
                        action,
                        100
                    ),

                targetUid:
                    targetUid
                        ? clean(
                              targetUid,
                              200
                          )
                        : null,

                details,

                createdAt:
                    FieldValue.serverTimestamp()
            });

    } catch (error) {

        /*
        Audit failure must NEVER
        bring down the main request.
        */

        console.error(
            "Audit log error:",
            error.message
        );
    }
}


/*
============================================================
 USER PROFILE CACHE
============================================================
*/

const profileCache =
    new Map();

const PROFILE_CACHE_TTL =
    30 * 1000;


function getCachedProfile(
    uid
) {

    const cached =
        profileCache.get(uid);

    if (!cached) {
        return null;
    }

    if (
        Date.now() -
            cached.time >
        PROFILE_CACHE_TTL
    ) {

        profileCache.delete(uid);

        return null;
    }

    return cached.profile;
}


function cacheProfile(
    uid,
    profile
) {

    profileCache.set(
        uid,
        {
            profile,
            time: Date.now()
        }
    );
}


/*
============================================================
 AUTHENTICATION
============================================================
*/

async function authenticate(
    req,
    res,
    next
) {

    try {

        const header =
            req.headers.authorization ||
            "";

        if (
            !header.startsWith(
                "Bearer "
            )
        ) {

            return res
                .status(401)
                .json({
                    success: false,
                    error:
                        "Authentication required."
                });
        }


        const token =
            header
                .substring(7)
                .trim();


        if (
            !token ||
            token.length > 10000
        ) {

            return res
                .status(401)
                .json({
                    success: false,
                    error:
                        "Invalid authentication token."
                });
        }


        /*
        ----------------------------------------------------
         Verify Firebase token and check revocation
        ----------------------------------------------------
        */

        const decoded =
            await auth.verifyIdToken(
                token,
                true
            );


        const uid =
            decoded.uid;


        /*
        ----------------------------------------------------
         Get profile from cache first
        ----------------------------------------------------
        */

        let profile =
            getCachedProfile(
                uid
            );


        if (!profile) {

            const profileSnap =
                await db
                    .collection(
                        "students"
                    )
                    .doc(uid)
                    .get();


            if (
                !profileSnap.exists
            ) {

                return res
                    .status(403)
                    .json({
                        success: false,
                        error:
                            "User profile not found."
                    });
            }


            profile =
                profileSnap.data();


            cacheProfile(
                uid,
                profile
            );
        }


        if (
            (
                profile.accountStatus ||
                "ACTIVE"
            ) !== "ACTIVE"
        ) {

            return res
                .status(403)
                .json({
                    success: false,
                    error:
                        "This account is blocked."
                });
        }


        const role =
            profile.role ||
            "STUDENT";


        const validRoles = [
            "STUDENT",
            "SECURITY",
            "ADMIN",
            "SUPER_ADMIN"
        ];


        if (
            !validRoles.includes(
                role
            )
        ) {

            return res
                .status(403)
                .json({
                    success: false,
                    error:
                        "Invalid account role."
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
                decoded.email ||
                "Unknown",

            studentId:
                profile.studentId ||
                "",

            studentType:
                profile.studentType ||
                "",

            role,

            accountStatus:
                profile.accountStatus ||
                "ACTIVE"
        };


        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error.code ||
                error.message
        );


        if (
            error.code ===
            "auth/id-token-revoked"
        ) {

            return res
                .status(401)
                .json({
                    success: false,
                    error:
                        "Session expired. Please login again."
                });
        }


        return res
            .status(401)
            .json({
                success: false,
                error:
                    "Authentication failed."
            });
    }
}


/*
============================================================
 ROLE PROTECTION
============================================================
*/

function requireRoles(
    ...roles
) {

    return (
        req,
        res,
        next
    ) => {

        if (
            !req.user ||
            !roles.includes(
                req.user.role
            )
        ) {

            return res
                .status(403)
                .json({
                    success: false,
                    error:
                        "You are not authorized."
                });
        }

        next();
    };
}


/*
============================================================
 QR CREATION
============================================================
*/

function createSignature(
    data
) {

    return crypto
        .createHmac(
            "sha256",
            QR_SECRET
        )
        .update(data)
        .digest("base64url");
}


function createQR(
    user
) {

    const now =
        Math.floor(
            Date.now() / 1000
        );


    const payload = {

        v: 1,

        uid:
            user.uid,

        studentId:
            user.studentId,

        iat:
            now,

        exp:
            now + QR_TTL,

        nonce:
            crypto
                .randomBytes(32)
                .toString("hex")
    };


    const encoded =
        Buffer
            .from(
                JSON.stringify(
                    payload
                )
            )
            .toString(
                "base64url"
            );


    const signature =
        createSignature(
            encoded
        );


    return {

        token:
            `${encoded}.${signature}`,

        issuedAt:
            now,

        expiresAt:
            now + QR_TTL
    };
}


function verifyQR(
    token
) {

    if (!token) {
        throw new Error(
            "QR code is required."
        );
    }


    if (
        token.length > 10000
    ) {
        throw new Error(
            "QR code is too large."
        );
    }


    const parts =
        token.split(".");


    if (
        parts.length !== 2
    ) {

        throw new Error(
            "Invalid QR code."
        );
    }


    const encoded =
        parts[0];

    const signature =
        parts[1];


    const expected =
        createSignature(
            encoded
        );


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
                    .toString(
                        "utf8"
                    )
            );

    } catch (_) {

        throw new Error(
            "Invalid QR data."
        );
    }


    const now =
        Math.floor(
            Date.now() / 1000
        );


    if (
        payload.v !== 1
    ) {

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


    if (
        typeof payload.uid !==
            "string" ||
        typeof payload.studentId !==
            "string" ||
        typeof payload.nonce !==
            "string"
    ) {

        throw new Error(
            "Invalid QR fields."
        );
    }


    if (
        payload.exp <= now
    ) {

        throw new Error(
            "QR code has expired."
        );
    }


    if (
        payload.iat > now + 5
    ) {

        throw new Error(
            "Invalid QR issue time."
        );
    }


    if (
        payload.exp -
            payload.iat >
        QR_TTL + 5
    ) {

        throw new Error(
            "Invalid QR lifetime."
        );
    }


    return payload;
}


/*
============================================================
 STATUS
============================================================
*/

app.get(
    "/api/status",
    (req, res) => {

        res.json({

            success: true,

            status: "online",

            environment:
                process.env.NODE_ENV ||
                "development",

            time:
                new Date().toISOString()
        });
    }
);


/*
============================================================
 CURRENT USER
============================================================
*/

app.get(
    "/api/me",
    authenticate,
    async (
        req,
        res
    ) => {

        res.json({

            success: true,

            user:
                req.user,

            role:
                req.user.role
        });
    }
);


/*
============================================================
 GENERATE STUDENT QR
============================================================
*/

async function generateQR(
    req,
    res
) {

    try {

        if (
            req.user.role !==
            "STUDENT"
        ) {

            return res
                .status(403)
                .json({
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


        snapshot.forEach(
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

            return res
                .status(429)
                .json({

                    success: false,

                    error:
                        "Daily entry limit reached.",

                    dailyCount:
                        todayCount,

                    dailyLimit:
                        DAILY_LIMIT
                });
        }


        const qr =
            createQR(
                req.user
            );


        /*
        Audit is intentionally not
        allowed to block QR creation.
        */

        audit(
            req.user.uid,
            req.user.role,
            "QR_GENERATED",
            req.user.uid
        );


        return res.json({

            success: true,

            qrData:
                qr.token,

            token:
                qr.token,

            issuedAt:
                qr.issuedAt,

            expiresAt:
                qr.expiresAt,

            qr: {

                token:
                    qr.token,

                issuedAt:
                    new Date(
                        qr.issuedAt *
                        1000
                    ).toISOString(),

                expiresAt:
                    new Date(
                        qr.expiresAt *
                        1000
                    ).toISOString()
            },

            dailyCount:
                todayCount,

            dailyLimit:
                DAILY_LIMIT
        });

    } catch (error) {

        console.error(
            "QR generation error:",
            error.message
        );

        return res
            .status(500)
            .json({
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


/*
============================================================
 VERIFY QR
============================================================
*/

app.post(
    "/api/verify-qr",
    qrLimiter,
    authenticate,
    requireRoles(
        "SECURITY",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const token =
                clean(
                    req.body.qrData ||
                    req.body.token ||
                    req.body.qr,
                    10000
                );


            const payload =
                verifyQR(
                    token
                );


            const studentSnap =
                await db
                    .collection(
                        "students"
                    )
                    .doc(
                        payload.uid
                    )
                    .get();


            if (
                !studentSnap.exists
            ) {

                throw new Error(
                    "Student account not found."
                );
            }


            const student =
                studentSnap.data();


            if (
                (
                    student.accountStatus ||
                    "ACTIVE"
                ) !== "ACTIVE"
            ) {

                throw new Error(
                    "Student account is blocked."
                );
            }


            if (
                clean(
                    student.studentId
                ) !==
                clean(
                    payload.studentId
                )
            ) {

                throw new Error(
                    "Student ID verification failed."
                );
            }


            const today =
                getToday();


            /*
            ------------------------------------------------
             IMPORTANT:
             The daily counter is stored in Firestore and
             updated inside the SAME transaction as the
             QR nonce and entry.

             This prevents multiple simultaneous scanners
             from bypassing the 3-entry limit.
            ------------------------------------------------
            */

            const counterId =
                `${payload.uid}_${today}`;

            const counterRef =
                db
                    .collection(
                        "dailyEntryCounters"
                    )
                    .doc(
                        counterId
                    );


            const nonceRef =
                db
                    .collection(
                        "usedQRNonces"
                    )
                    .doc(
                        payload.nonce
                    );


            const entryRef =
                db
                    .collection(
                        "entries"
                    )
                    .doc();


            const result =
                await db.runTransaction(
                    async transaction => {

                        /*
                        ------------------------------------
                         READS
                        ------------------------------------
                        */

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


                        const counterSnap =
                            await transaction.get(
                                counterRef
                            );


                        let todayCount = 0;


                        if (
                            counterSnap.exists
                        ) {

                            todayCount =
                                Number(
                                    counterSnap
                                        .data()
                                        .count ||
                                    0
                                );
                        }


                        /*
                        ------------------------------------
                         ATOMIC DAILY LIMIT
                        ------------------------------------
                        */

                        if (
                            todayCount >=
                            DAILY_LIMIT
                        ) {

                            throw new Error(
                                "Student has reached the daily entry limit."
                            );
                        }


                        const newCount =
                            todayCount + 1;


                        /*
                        ------------------------------------
                         CREATE ENTRY
                        ------------------------------------
                        */

                        transaction.create(
                            entryRef,
                            {

                                studentUid:
                                    payload.uid,

                                studentId:
                                    student.studentId ||
                                    "",

                                studentName:
                                    student.name ||
                                    "",

                                studentEmail:
                                    student.email ||
                                    "",

                                studentType:
                                    student.studentType ||
                                    "",


                                /*
                                Human-readable verifier
                                */

                                verifiedBy:
                                    req.user.name ||
                                    req.user.email ||
                                    "Unknown",


                                verifiedByUid:
                                    req.user.uid,


                                verifiedByRole:
                                    req.user.role,


                                verifierUid:
                                    req.user.uid,


                                verifierName:
                                    req.user.name ||
                                    req.user.email ||
                                    "Unknown",


                                verifierRole:
                                    req.user.role,


                                dayKey:
                                    today,


                                status:
                                    "ALLOWED",


                                qrNonce:
                                    payload.nonce,


                                createdAt:
                                    FieldValue.serverTimestamp()
                            }
                        );


                        /*
                        ------------------------------------
                         MARK QR AS USED
                        ------------------------------------
                        */

                        transaction.create(
                            nonceRef,
                            {

                                uid:
                                    payload.uid,

                                studentId:
                                    payload.studentId,

                                usedBy:
                                    req.user.uid,

                                usedByName:
                                    req.user.name ||
                                    req.user.email ||
                                    "Unknown",

                                usedByRole:
                                    req.user.role,

                                usedAt:
                                    FieldValue.serverTimestamp(),

                                expiresAt:
                                    payload.exp
                            }
                        );


                        /*
                        ------------------------------------
                         UPDATE ATOMIC COUNTER
                        ------------------------------------
                        */

                        transaction.set(
                            counterRef,
                            {

                                studentUid:
                                    payload.uid,

                                dayKey:
                                    today,

                                count:
                                    newCount,

                                updatedAt:
                                    FieldValue.serverTimestamp()

                            },
                            {
                                merge: true
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


            /*
            ------------------------------------------------
             AUDIT DOES NOT BLOCK RESPONSE
            ------------------------------------------------
            */

            audit(
                req.user.uid,
                req.user.role,
                "ENTRY_ALLOWED",
                payload.uid,
                {
                    studentId:
                        student.studentId ||
                        "",

                    entryId:
                        result.entryId
                }
            );


            return res.json({

                success: true,

                status:
                    "ALLOWED",

                message:
                    "Entry verified successfully.",

                student: {

                    uid:
                        payload.uid,

                    studentId:
                        student.studentId ||
                        "",

                    name:
                        student.name ||
                        "",

                    studentType:
                        student.studentType ||
                        "",

                    accountStatus:
                        student.accountStatus ||
                        "ACTIVE"
                },

                entry: {

                    entryId:
                        result.entryId,

                    dailyCount:
                        result.dailyCount,

                    dailyLimit:
                        result.dailyLimit,

                    remainingEntries:
                        result.remainingEntries
                }
            });

        } catch (error) {

            console.error(
                "QR verification error:",
                error.message
            );


            return res
                .status(400)
                .json({

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


/*
============================================================
 RESOLVE OLD VERIFIER UID -> NAME
============================================================
*/

async function resolveVerifierNames(
    entries
) {

    const uidSet =
        new Set();


    for (
        const entry of entries
    ) {

        const uid =
            entry.verifierUid ||
            entry.verifiedByUid ||
            entry.verifiedBy;


        /*
        Firebase UIDs are generally
        longer than normal names.
        */

        if (
            uid &&
            typeof uid ===
                "string" &&
            uid.length > 20
        ) {

            uidSet.add(
                uid
            );
        }
    }


    if (
        uidSet.size === 0
    ) {

        return entries;
    }


    const uidList =
        Array.from(
            uidSet
        );


    const refs =
        uidList.map(
            uid =>
                db
                    .collection(
                        "students"
                    )
                    .doc(uid)
        );


    const snapshots =
        await db.getAll(
            ...refs
        );


    const nameMap =
        new Map();


    snapshots.forEach(
        (
            snap,
            index
        ) => {

            if (
                snap.exists
            ) {

                const data =
                    snap.data();


                nameMap.set(
                    uidList[index],
                    data.name ||
                    data.displayName ||
                    data.email ||
                    "Unknown"
                );
            }
        }
    );


    return entries.map(
        entry => {

            const uid =
                entry.verifierUid ||
                entry.verifiedByUid ||
                entry.verifiedBy;


            const name =
                entry.verifierName ||
                nameMap.get(
                    uid
                ) ||
                (
                    uid &&
                    uid.length <= 20
                        ? uid
                        : "Unknown"
                );


            return {

                ...entry,

                verifiedBy:
                    name,

                verifiedByUid:
                    uid || "",

                verifierName:
                    name
            };
        }
    );
}


/*
============================================================
 STUDENT HISTORY
============================================================
*/

app.get(
    "/api/entries/:studentId",
    authenticate,
    async (
        req,
        res
    ) => {

        try {

            const studentId =
                clean(
                    req.params.studentId,
                    100
                );


            if (
                req.user.role ===
                    "STUDENT" &&
                studentId !==
                    req.user.studentId
            ) {

                return res
                    .status(403)
                    .json({
                        success: false,
                        error:
                            "You can only view your own history."
                    });
            }


            const snapshot =
                await db
                    .collection(
                        "entries"
                    )
                    .where(
                        "studentId",
                        "==",
                        studentId
                    )
                    .limit(200)
                    .get();


            let entries =
                snapshot.docs
                    .map(
                        doc => ({
                            id:
                                doc.id,

                            ...doc.data()
                        })
                    )
                    .sort(
                        (
                            a,
                            b
                        ) => {

                            const aTime =
                                safeDate(
                                    a.createdAt
                                )?.getTime() ||
                                0;

                            const bTime =
                                safeDate(
                                    b.createdAt
                                )?.getTime() ||
                                0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    )
                    .slice(
                        0,
                        100
                    );


            entries =
                await resolveVerifierNames(
                    entries
                );


            return res.json({

                success: true,

                entries
            });

        } catch (error) {

            console.error(
                "History error:",
                error.message
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load entry history."
                });
        }
    }
);


/*
============================================================
 STAFF / ADMIN HISTORY
============================================================
*/

app.get(
    "/api/admin/entries",
    authenticate,
    requireRoles(
        "SECURITY",
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const snapshot =
                await db
                    .collection(
                        "entries"
                    )
                    .limit(200)
                    .get();


            let entries =
                snapshot.docs
                    .map(
                        doc => ({
                            id:
                                doc.id,

                            ...doc.data()
                        })
                    )
                    .sort(
                        (
                            a,
                            b
                        ) => {

                            const aTime =
                                safeDate(
                                    a.createdAt
                                )?.getTime() ||
                                0;

                            const bTime =
                                safeDate(
                                    b.createdAt
                                )?.getTime() ||
                                0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    );


            entries =
                await resolveVerifierNames(
                    entries
                );


            return res.json({

                success: true,

                entries
            });

        } catch (error) {

            console.error(
                "Staff history error:",
                error.message
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load entry history."
                });
        }
    }
);


/*
============================================================
 AUTOMATIC ID GENERATOR
============================================================
*/

async function generateNextId(
    prefix
) {

    const counterRef =
        db
            .collection(
                "idCounters"
            )
            .doc(
                prefix
            );


    return db.runTransaction(
        async transaction => {

            const snap =
                await transaction.get(
                    counterRef
                );


            let nextNumber =
                1001;


            if (
                snap.exists
            ) {

                nextNumber =
                    (
                        Number(
                            snap.data()
                                .lastNumber
                        ) ||
                        1000
                    ) + 1;

            } else {

                /*
                First creation for this
                prefix.
                */

                const snapshot =
                    await db
                        .collection(
                            "students"
                        )
                        .get();


                let maxNumber =
                    1000;


                const escapedPrefix =
                    prefix.replace(
                        /[.*+?^${}()|[\]\\]/g,
                        "\\$&"
                    );


                snapshot.forEach(
                    doc => {

                        const id =
                            String(
                                doc.data()
                                    .studentId ||
                                ""
                            );


                        const match =
                            id.match(
                                new RegExp(
                                    "^" +
                                    escapedPrefix +
                                    "-(\\d+)$"
                                )
                            );


                        if (
                            match
                        ) {

                            maxNumber =
                                Math.max(
                                    maxNumber,
                                    Number(
                                        match[1]
                                    )
                                );
                        }
                    }
                );


                nextNumber =
                    maxNumber + 1;
            }


            transaction.set(
                counterRef,
                {

                    prefix,

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
    ).then(
        number =>
            `${prefix}-${number}`
    );
}


/*
============================================================
 SUPER ADMIN CREATE USER
============================================================
*/

app.post(
    "/api/super-admin/create-user",
    adminLimiter,
    authenticate,
    requireRoles(
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const name =
                clean(
                    req.body.name,
                    200
                );

            const email =
                clean(
                    req.body.email,
                    200
                )
                .toLowerCase();


            const password =
                String(
                    req.body.password ||
                    ""
                );


            const role =
                clean(
                    req.body.role,
                    50
                )
                .toUpperCase();


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
                !allowedRoles.includes(
                    role
                )
            ) {

                return res
                    .status(400)
                    .json({
                        success: false,
                        error:
                            "Invalid role."
                    });
            }


            if (
                !name ||
                !email ||
                password.length < 8
            ) {

                return res
                    .status(400)
                    .json({
                        success: false,
                        error:
                            "Valid name, email and password are required."
                    });
            }


            const prefix =
                role === "STUDENT"
                    ? "SRMAP-STU"
                    : role === "SECURITY"
                        ? "SRMAP-SEC"
                        : role === "ADMIN"
                            ? "SRMAP-ADM"
                            : "SRMAP-SADM";


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
                    .collection(
                        "students"
                    )
                    .doc(
                        user.uid
                    )
                    .set({

                        uid:
                            user.uid,

                        email,

                        name,

                        studentId:
                            generatedId,

                        studentType:
                            role === "STUDENT"
                                ? (
                                    studentType ||
                                    "Day Scholar"
                                )
                                : "STAFF",

                        role,

                        accountStatus:
                            "ACTIVE",

                        createdAt:
                            FieldValue.serverTimestamp(),

                        createdBy:
                            req.user.uid
                    });

            } catch (error) {

                try {

                    await auth.deleteUser(
                        user.uid
                    );

                } catch (_) {}

                throw error;
            }


            await audit(
                req.user.uid,
                req.user.role,
                "USER_CREATED",
                user.uid,
                {
                    role,

                    studentId:
                        generatedId
                }
            );


            return res
                .status(201)
                .json({

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
                "Create user error:",
                error.message
            );


            if (
                error.code ===
                "auth/email-already-exists"
            ) {

                return res
                    .status(409)
                    .json({
                        success: false,
                        error:
                            "An account with this email already exists."
                    });
            }


            return res
                .status(500)
                .json({
                    success: false,
                    error:
                        "Unable to create user."
                });
        }
    }
);


/*
============================================================
 CREATE STUDENT
============================================================
*/

app.post(
    "/api/students",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const email =
                clean(
                    req.body.email,
                    200
                )
                .toLowerCase();


            const password =
                String(
                    req.body.password ||
                    ""
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

                return res
                    .status(400)
                    .json({
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
                    .collection(
                        "students"
                    )
                    .doc(
                        user.uid
                    )
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

            } catch (error) {

                try {

                    await auth.deleteUser(
                        user.uid
                    );

                } catch (_) {}

                throw error;
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


            return res.json({

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
                error.message
            );


            return res
                .status(400)
                .json({

                    success: false,

                    error:
                        error.message ||
                        "Could not create student."
                });
        }
    }
);


/*
============================================================
 CREATE STAFF
============================================================
*/

app.post(
    "/api/admins",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const email =
                clean(
                    req.body.email,
                    200
                )
                .toLowerCase();


            const password =
                String(
                    req.body.password ||
                    ""
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
                )
                .toUpperCase();


            if (
                ![
                    "SECURITY",
                    "ADMIN",
                    "SUPER_ADMIN"
                ].includes(
                    role
                )
            ) {

                return res
                    .status(400)
                    .json({
                        success: false,
                        error:
                            "Invalid staff role."
                    });
            }


            if (
                req.user.role !==
                    "SUPER_ADMIN" &&
                role ===
                    "SUPER_ADMIN"
            ) {

                return res
                    .status(403)
                    .json({
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

                return res
                    .status(400)
                    .json({
                        success: false,
                        error:
                            "Valid email, password and name are required."
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
                    .collection(
                        "students"
                    )
                    .doc(
                        user.uid
                    )
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

            } catch (error) {

                try {

                    await auth.deleteUser(
                        user.uid
                    );

                } catch (_) {}

                throw error;
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


            return res.json({

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
                error.message
            );


            return res
                .status(400)
                .json({

                    success: false,

                    error:
                        error.message ||
                        "Could not create staff."
                });
        }
    }
);


/*
============================================================
 ALL USERS
============================================================
*/

app.get(
    "/api/admin/users",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const snapshot =
                await db
                    .collection(
                        "students"
                    )
                    .limit(500)
                    .get();


            const users =
                snapshot.docs
                    .map(
                        doc => ({
                            uid:
                                doc.id,

                            ...doc.data()
                        })
                    )
                    .sort(
                        (
                            a,
                            b
                        ) =>
                            String(
                                a.name ||
                                ""
                            ).localeCompare(
                                String(
                                    b.name ||
                                    ""
                                )
                            )
                    );


            return res.json({

                success: true,

                users
            });

        } catch (error) {

            console.error(
                "Users list error:",
                error.message
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load users."
                });
        }
    }
);


/*
============================================================
 STUDENTS
============================================================
*/

app.get(
    "/api/students",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const snapshot =
                await db
                    .collection(
                        "students"
                    )
                    .where(
                        "role",
                        "==",
                        "STUDENT"
                    )
                    .limit(500)
                    .get();


            const students =
                snapshot.docs.map(
                    doc => ({
                        uid:
                            doc.id,

                        ...doc.data()
                    })
                );


            return res.json({

                success: true,

                students
            });

        } catch (error) {

            console.error(
                "Students list error:",
                error.message
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load students."
                });
        }
    }
);


/*
============================================================
 STAFF
============================================================
*/

app.get(
    "/api/admin/staff",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const snapshot =
                await db
                    .collection(
                        "students"
                    )
                    .where(
                        "role",
                        "in",
                        [
                            "SECURITY",
                            "ADMIN",
                            "SUPER_ADMIN"
                        ]
                    )
                    .limit(500)
                    .get();


            const staff =
                snapshot.docs.map(
                    doc => ({
                        uid:
                            doc.id,

                        ...doc.data()
                    })
                );


            return res.json({

                success: true,

                staff
            });

        } catch (error) {

            console.error(
                "Staff list error:",
                error.message
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load staff."
                });
        }
    }
);


/*
============================================================
 BLOCK / ACTIVATE USER
============================================================
*/

app.post(
    "/api/users/:uid/status",
    adminLimiter,
    authenticate,
    requireRoles(
        "ADMIN",
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

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
                )
                .toUpperCase();


            if (
                uid ===
                req.user.uid
            ) {

                return res
                    .status(403)
                    .json({
                        success: false,
                        error:
                            "You cannot change your own account status."
                    });
            }


            if (
                ![
                    "ACTIVE",
                    "BLOCKED"
                ].includes(
                    status
                )
            ) {

                return res
                    .status(400)
                    .json({
                        success: false,
                        error:
                            "Invalid account status."
                    });
            }


            const ref =
                db
                    .collection(
                        "students"
                    )
                    .doc(uid);


            const snap =
                await ref.get();


            if (
                !snap.exists
            ) {

                return res
                    .status(404)
                    .json({
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

                return res
                    .status(403)
                    .json({
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
                        status ===
                        "BLOCKED"
                }
            );


            profileCache.delete(
                uid
            );


            await audit(
                req.user.uid,
                req.user.role,
                status ===
                    "BLOCKED"
                    ? "USER_BLOCKED"
                    : "USER_UNBLOCKED",
                uid
            );


            return res.json({

                success: true,

                message:
                    status ===
                    "BLOCKED"
                        ? "User blocked."
                        : "User activated."
            });

        } catch (error) {

            console.error(
                "Status update error:",
                error.message
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to update account status."
                });
        }
    }
);


/*
============================================================
 AUDIT LOGS
============================================================
*/

app.get(
    "/api/admin/audit-logs",
    adminLimiter,
    authenticate,
    requireRoles(
        "SUPER_ADMIN"
    ),
    async (
        req,
        res
    ) => {

        try {

            const snapshot =
                await db
                    .collection(
                        "auditLogs"
                    )
                    .limit(200)
                    .get();


            const logs =
                snapshot.docs
                    .map(
                        doc => ({
                            id:
                                doc.id,

                            ...doc.data()
                        })
                    )
                    .sort(
                        (
                            a,
                            b
                        ) => {

                            const aTime =
                                safeDate(
                                    a.createdAt
                                )?.getTime() ||
                                0;

                            const bTime =
                                safeDate(
                                    b.createdAt
                                )?.getTime() ||
                                0;

                            return (
                                bTime -
                                aTime
                            );
                        }
                    );


            return res.json({

                success: true,

                logs
            });

        } catch (error) {

            console.error(
                "Audit list error:",
                error.message
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to load audit logs."
                });
        }
    }
);


/*
============================================================
 LOGOUT
============================================================
*/

app.post(
    "/api/logout",
    authLimiter,
    authenticate,
    async (
        req,
        res
    ) => {

        audit(
            req.user.uid,
            req.user.role,
            "LOGOUT"
        );


        return res.json({

            success: true
        });
    }
);


/*
============================================================
 STATIC WEBSITE
============================================================
*/

/*
IMPORTANT:
Only files inside /public are exposed.

firebase-service-account.json
.env
server.js
package.json

are NOT publicly accessible.
*/

if (
    fs.existsSync(
        PUBLIC_DIR
    )
) {

    app.use(
        express.static(
            PUBLIC_DIR,
            {

                extensions: [
                    "html"
                ],

                dotfiles:
                    "deny",

                index:
                    "index.html",

                maxAge:
                    process.env.NODE_ENV ===
                    "production"
                        ? "1h"
                        : 0
            }
        )
    );

} else {

    console.error(
        "WARNING: public folder does not exist."
    );
}


/*
============================================================
 API 404
============================================================
*/

app.use(
    "/api",
    (
        req,
        res
    ) => {

        return res
            .status(404)
            .json({

                success: false,

                error:
                    "API endpoint not found."
            });
    }
);


/*
============================================================
 GLOBAL ERROR HANDLER
============================================================
*/

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Unhandled Express error:",
            error.message
        );


        if (
            res.headersSent
        ) {

            return next(
                error
            );
        }


        return res
            .status(500)
            .json({

                success: false,

                error:
                    "Internal server error."
            });
    }
);


/*
============================================================
 START SERVER
============================================================
*/

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
                " SRM AP DAYPASS SERVER"
            );
            console.log(
                "========================================"
            );
            console.log(
                `Server running on port ${PORT}`
            );
            console.log(
                "Firebase authentication enabled"
            );
            console.log(
                "Secure QR enabled"
            );
            console.log(
                "Atomic daily entry limit enabled"
            );
            console.log(
                "One-time QR protection enabled"
            );
            console.log(
                "Human verifier names enabled"
            );
            console.log(
                "Rate limiting enabled"
            );
            console.log(
                "Protected public directory enabled"
            );
            console.log(
                "========================================"
            );
            console.log("");
        }
    );


/*
============================================================
 SERVER TIMEOUTS
============================================================
*/

server.requestTimeout =
    30 * 1000;

server.headersTimeout =
    35 * 1000;

server.keepAliveTimeout =
    5 * 1000;


/*
============================================================
 SERVER ERROR
============================================================
*/

server.on(
    "error",
    error => {

        console.error(
            "HTTP server error:",
            error.message
        );


        /*
        Do not immediately kill the server
        for ordinary HTTP errors.
        */

        if (
            error.code ===
            "EADDRINUSE"
        ) {

            console.error(
                `Port ${PORT} is already in use.`
            );

            process.exit(1);
        }
    }
);


/*
============================================================
 PROCESS ERROR HANDLING
============================================================
*/

/*
A truly fatal Node process error should not
leave the application in an unknown state.

The hosting platform can restart it.
*/

process.on(
    "uncaughtException",
    error => {

        console.error(
            "FATAL uncaught exception:",
            error
        );

        server.close(
            () => {
                process.exit(1);
            }
        );
    }
);


process.on(
    "unhandledRejection",
    reason => {

        console.error(
            "FATAL unhandled promise rejection:",
            reason
        );

        server.close(
            () => {
                process.exit(1);
            }
        );
    }
);


/*
============================================================
 GRACEFUL SHUTDOWN
============================================================
*/

let shuttingDown =
    false;


async function shutdown(
    signal
) {

    if (
        shuttingDown
    ) {
        return;
    }


    shuttingDown =
        true;


    console.log(
        `${signal} received. Shutting down safely...`
    );


    server.close(
        async () => {

            try {

                /*
                Give active Firebase requests
                a short opportunity to finish.
                */

                await new Promise(
                    resolve =>
                        setTimeout(
                            resolve,
                            1000
                        )
                );

            } catch (_) {}


            process.exit(0);
        }
    );


    setTimeout(
        () => {
            process.exit(1);
        },
        10000
    ).unref();
}


process.on(
    "SIGINT",
    () =>
        shutdown(
            "SIGINT"
        )
);


process.on(
    "SIGTERM",
    () =>
        shutdown(
            "SIGTERM"
        )
);