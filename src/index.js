export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const json = (data, status = 200) =>
      Response.json(data, {
        status,
        headers: { "Cache-Control": "no-store" }
      });

    const optionalText = (value, maxLength) => {
      if (value == null || value === "") return null;
      if (typeof value !== "string") return undefined;

      const text = value.trim();
      return text.length <= maxLength ? text : undefined;
    };

    const asFlag = (value) =>
      value === true || value === 1 || value === "1" ? 1 : 0;

    // 관리자 로그인 토큰 생성 및 검증
    const base64UrlEncode = (text) =>
      btoa(text)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");

    const base64UrlDecode = (text) => {
      const base64 = text
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      return atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
    };

    const getAdminKey = async () => {
      if (!env.MUT_ADMIN_PASSWORD) {
        throw new Error("MUT_ADMIN_PASSWORD secret is missing");
      }

      return crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(env.MUT_ADMIN_PASSWORD),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );
    };

    const createAdminToken = async () => {
      const payload = base64UrlEncode(
        JSON.stringify({
          role: "admin",
          exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
        })
      );

      const key = await getAdminKey();
      const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(payload)
      );

      const signatureText = base64UrlEncode(
        String.fromCharCode(...new Uint8Array(signature))
      );

      return `${payload}.${signatureText}`;
    };

    const verifyAdminToken = async (token) => {
      try {
        if (typeof token !== "string") return false;

        const parts = token.split(".");
        if (parts.length !== 2) return false;

        const [payload, signatureText] = parts;
        const signatureBinary = base64UrlDecode(signatureText);
        const signatureBytes = Uint8Array.from(
          signatureBinary,
          (char) => char.charCodeAt(0)
        );

        const key = await getAdminKey();
        const valid = await crypto.subtle.verify(
          "HMAC",
          key,
          signatureBytes,
          new TextEncoder().encode(payload)
        );

        if (!valid) return false;

        const data = JSON.parse(base64UrlDecode(payload));

        return data.role === "admin" &&
          Number.isFinite(data.exp) &&
          data.exp > Math.floor(Date.now() / 1000);
      } catch {
        return false;
      }
    };

    try {
      // 관리자 로그인
      if (path === "/api/admin/login" && method === "POST") {
        if (
          typeof env.MUT_ADMIN_PASSWORD !== "string" ||
          env.MUT_ADMIN_PASSWORD.length === 0
        ) {
          return json({
            ok: false,
            error: "Admin login is not configured"
          }, 500);
        }

        let body;

        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }

        if (
          typeof body.password !== "string" ||
          body.password.length === 0 ||
          body.password !== env.MUT_ADMIN_PASSWORD
        ) {
          return json({ ok: false, error: "Invalid password" }, 401);
        }

        const token = await createAdminToken();

        return json({
          ok: true,
          token,
          expiresIn: 28800
        });
      }

      // 관리자 전용 API 인증
      if (
        path.startsWith("/api/admin/") &&
        path !== "/api/admin/login"
      ) {
        const authorization = request.headers.get("Authorization") || "";
        const token = authorization.startsWith("Bearer ")
          ? authorization.slice(7)
          : "";

        if (!(await verifyAdminToken(token))) {
          return json({ ok: false, error: "Unauthorized" }, 401);
        }
      }


      // SPONSOR: public logos; admin actions are protected by the authentication gate above.
      if (path === "/api/sponsors" && method === "GET") {
        const rows = await env.DB.prepare(`
          SELECT id, name, image_url, sort_order
          FROM sponsors ORDER BY sort_order ASC, id ASC
        `).all();
        return json({ ok: true, sponsors: rows.results || [] });
      }

      if (path === "/api/admin/sponsors" && method === "GET") {
        const rows = await env.DB.prepare(`
          SELECT id, name, image_url, sort_order, created_at
          FROM sponsors ORDER BY sort_order ASC, id ASC
        `).all();
        return json({ ok: true, sponsors: rows.results || [] });
      }

      // Permit HTTPS URLs, or explicitly typed PNG/JPEG/WebP raster data only.
      const validSponsorImage = (value) => {
        if (typeof value !== "string" || !value) return false;
        if (/^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(value)) {
          return value.length <= 350000;
        }
        if (value.length > 2048) return false;
        try { const u = new URL(value); return u.protocol === "https:"; }
        catch { return false; }
      };

      if (path === "/api/admin/sponsors" && method === "POST") {
        let body;
        try { body = await request.json(); } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }
        const name = optionalText(body?.name, 120);
        const imageUrl = body?.image_url;
        const sortOrder = Number(body?.sort_order ?? 0);
        if (!name || !validSponsorImage(imageUrl) ||
            !Number.isSafeInteger(sortOrder) || sortOrder < 0 || sortOrder > 100000) {
          return json({ ok: false, error: "Invalid sponsor fields" }, 400);
        }
        const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM sponsors").first();
        if (Number(count?.count || 0) >= 100) {
          return json({ ok: false, error: "Sponsor limit reached" }, 400);
        }
        const row = await env.DB.prepare(
          "INSERT INTO sponsors (name, image_url, sort_order) VALUES (?, ?, ?)"
        ).bind(name, imageUrl, sortOrder).run();
        return json({ ok: true, id: row.meta.last_row_id }, 201);
      }

      const sponsorMatch = path.match(/^\/api\/admin\/sponsors\/(\d+)$/);
      if (sponsorMatch && method === "PUT") {
        let body;
        try { body = await request.json(); } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }
        const name = optionalText(body?.name, 120);
        const imageUrl = body?.image_url;
        const sortOrder = Number(body?.sort_order ?? 0);
        if (!name || !validSponsorImage(imageUrl) ||
            !Number.isSafeInteger(sortOrder) || sortOrder < 0 || sortOrder > 100000) {
          return json({ ok: false, error: "Invalid sponsor fields" }, 400);
        }
        const result = await env.DB.prepare(
          "UPDATE sponsors SET name = ?, image_url = ?, sort_order = ? WHERE id = ?"
        ).bind(name, imageUrl, sortOrder, Number(sponsorMatch[1])).run();
        return result.meta.changes ? json({ ok: true })
          : json({ ok: false, error: "Sponsor not found" }, 404);
      }
      if (sponsorMatch && method === "DELETE") {
        const result = await env.DB.prepare("DELETE FROM sponsors WHERE id = ?")
          .bind(Number(sponsorMatch[1])).run();
        return result.meta.changes ? json({ ok: true })
          : json({ ok: false, error: "Sponsor not found" }, 404);
      }

      // 관리자 대회 관리 API
      if (path === "/api/admin/events" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, name, event_date, venue, event_time, description,
                 registration_open, participants_public,
                 early_bird_start, early_bird_end,
                 registration_start, registration_end, poster_url, photo_url, created_at
          FROM events
          ORDER BY event_date ASC, id DESC
        `).all();

        return json({ ok: true, events: result.results });
      }

      if (path === "/api/admin/events" && method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }

        const name = optionalText(body.name, 200);
        const eventDate = optionalText(body.event_date, 10);
        const venue = optionalText(body.venue, 200);
        const eventTime = optionalText(body.event_time, 20);
        const description = optionalText(body.description, 5000);
        const earlyStart = optionalText(body.early_bird_start, 10);
        const earlyEnd = optionalText(body.early_bird_end, 10);
        const registrationStart = optionalText(body.registration_start, 10);
        const registrationEnd = optionalText(body.registration_end, 10);
        const posterUrl = optionalText(body.poster_url, 2000);
        const photoUrl = optionalText(body.photo_url, 2000);
        if(photoUrl){try{const u=new URL(photoUrl);if(u.protocol!=="https:"||!["drive.google.com","docs.google.com"].includes(u.hostname))return json({ok:false,error:"Invalid Google Drive URL"},400);}catch{return json({ok:false,error:"Invalid Google Drive URL"},400);}}

        const values = [
          eventDate, venue, eventTime, description, earlyStart,
          earlyEnd, registrationStart, registrationEnd, posterUrl, photoUrl
        ];

        if (!name || values.some(v => v === undefined)) {
          return json({ ok: false, error: "Invalid event fields" }, 400);
        }

        const result = await env.DB.prepare(`
          INSERT INTO events (
            name, event_date, venue, event_time, description,
            registration_open, participants_public,
            early_bird_start, early_bird_end,
            registration_start, registration_end, poster_url, photo_url
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          name, eventDate, venue, eventTime, description,
          asFlag(body.registration_open), asFlag(body.participants_public),
          earlyStart, earlyEnd, registrationStart, registrationEnd, posterUrl, photoUrl
        ).run();

        return json({ ok: true, id: result.meta.last_row_id }, 201);
      }

      const eventMatch = path.match(/^\/api\/admin\/events\/(\d+)$/);

      if (eventMatch && method === "PUT") {
        const id = Number(eventMatch[1]);
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }

        const name = optionalText(body.name, 200);
        const eventDate = optionalText(body.event_date, 10);
        const venue = optionalText(body.venue, 200);
        const eventTime = optionalText(body.event_time, 20);
        const description = optionalText(body.description, 5000);
        const earlyStart = optionalText(body.early_bird_start, 10);
        const earlyEnd = optionalText(body.early_bird_end, 10);
        const registrationStart = optionalText(body.registration_start, 10);
        const registrationEnd = optionalText(body.registration_end, 10);
        const posterUrl = optionalText(body.poster_url, 2000);
        const photoUrl = optionalText(body.photo_url, 2000);
        if(photoUrl){try{const u=new URL(photoUrl);if(u.protocol!=="https:"||!["drive.google.com","docs.google.com"].includes(u.hostname))return json({ok:false,error:"Invalid Google Drive URL"},400);}catch{return json({ok:false,error:"Invalid Google Drive URL"},400);}}

        const values = [
          eventDate, venue, eventTime, description, earlyStart,
          earlyEnd, registrationStart, registrationEnd, posterUrl, photoUrl
        ];

        if (!name || values.some(v => v === undefined)) {
          return json({ ok: false, error: "Invalid event fields" }, 400);
        }

        const result = await env.DB.prepare(`
          UPDATE events SET
            name = ?, event_date = ?, venue = ?, event_time = ?, description = ?,
            registration_open = ?, participants_public = ?,
            early_bird_start = ?, early_bird_end = ?,
            registration_start = ?, registration_end = ?, poster_url = ?, photo_url = ?
          WHERE id = ?
        `).bind(
          name, eventDate, venue, eventTime, description,
          asFlag(body.registration_open), asFlag(body.participants_public),
          earlyStart, earlyEnd, registrationStart, registrationEnd, posterUrl, photoUrl, id
        ).run();

        if (!result.meta.changes) {
          return json({ ok: false, error: "Event not found" }, 404);
        }

        return json({ ok: true });
      }

      if (eventMatch && method === "DELETE") {
        const id = Number(eventMatch[1]);

        const participant = await env.DB.prepare(
          "SELECT id FROM participants WHERE event_id = ? LIMIT 1"
        ).bind(id).first();

        if (participant) {
          return json({
            ok: false,
            error: "Participants exist; event cannot be deleted"
          }, 409);
        }

        const notice = await env.DB.prepare(
          "SELECT id FROM notices WHERE event_id = ? LIMIT 1"
        ).bind(id).first();

        if (notice) {
          return json({
            ok: false,
            error: "Notices exist; delete or reassign notices first"
          }, 409);
        }

        const result = await env.DB.prepare(
          "DELETE FROM events WHERE id = ?"
        ).bind(id).run();

        if (!result.meta.changes) {
          return json({ ok: false, error: "Event not found" }, 404);
        }

        return json({ ok: true });
      }

      // 관리자 랭킹 관리 API
      if (path === "/api/admin/rankings" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, player_name, affiliation, belt, gold, silver, bronze, points
          FROM rankings
          ORDER BY points DESC, gold DESC, silver DESC, bronze DESC, player_name ASC
        `).all();

        return json({ ok: true, rankings: result.results });
      }

      if (path === "/api/admin/rankings" && method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }

        const playerName = optionalText(body.player_name, 100);
        const affiliation = optionalText(body.affiliation, 150);
        const belt = optionalText(body.belt, 30);
        const medals = [body.gold ?? 0, body.silver ?? 0, body.bronze ?? 0].map(Number);

        if (
          !playerName || !affiliation || !belt ||
          medals.some(v => !Number.isSafeInteger(v) || v < 0 || v > 100000)
        ) {
          return json({ ok: false, error: "Invalid ranking fields" }, 400);
        }

        const points = medals[0] * 5 + medals[1] * 3 + medals[2];

        const result = await env.DB.prepare(`
          INSERT INTO rankings (player_name, affiliation, belt, gold, silver, bronze, points)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(player_name, affiliation, belt) DO UPDATE SET
            gold = excluded.gold, silver = excluded.silver,
            bronze = excluded.bronze, points = excluded.points
        `).bind(
          playerName, affiliation, belt,
          medals[0], medals[1], medals[2], points
        ).run();

        return json({ ok: true, changes: result.meta.changes });
      }
            const rankingMatch = path.match(/^\/api\/admin\/rankings\/(\d+)$/);
      if (rankingMatch && method === "PUT") {
        const id = Number(rankingMatch[1]);
        let body;
        try { body = await request.json(); } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }
        const playerName = optionalText(body.player_name, 100);
        const affiliation = optionalText(body.affiliation, 150);
        const belt = optionalText(body.belt, 30);
        const medals = [body.gold ?? 0, body.silver ?? 0, body.bronze ?? 0].map(Number);
        if (!playerName || !affiliation || !belt || medals.some(v => !Number.isSafeInteger(v) || v < 0 || v > 100000)) {
          return json({ ok: false, error: "Invalid ranking fields" }, 400);
        }
        const points = medals[0] * 5 + medals[1] * 3 + medals[2];
        const result = await env.DB.prepare(`
          UPDATE rankings SET player_name = ?, affiliation = ?, belt = ?,
            gold = ?, silver = ?, bronze = ?, points = ? WHERE id = ?
        `).bind(playerName, affiliation, belt, medals[0], medals[1], medals[2], points, id).run();
        if (!result.meta.changes) return json({ ok: false, error: "Ranking not found" }, 404);
        return json({ ok: true });
      }

      if (rankingMatch && method === "DELETE") {
        const result = await env.DB.prepare("DELETE FROM rankings WHERE id = ?")
          .bind(Number(rankingMatch[1])).run();
        if (!result.meta.changes) return json({ ok: false, error: "Ranking not found" }, 404);
        return json({ ok: true });
      }

      // 관리자 공지사항 관리 API
      if (path === "/api/admin/notices" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, event_id, title, content, published, created_at
          FROM notices ORDER BY id DESC
        `).all();
        return json({ ok: true, notices: result.results });
      }

      if (path === "/api/admin/notices" && method === "POST") {
        let body;
        try { body = await request.json(); } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }
        const title = optionalText(body.title, 200);
        const content = optionalText(body.content, 10000);
        const eventId = body.event_id == null || body.event_id === "" ? null : Number(body.event_id);
        if (!title || !content || (body.event_id != null && body.event_id !== "" && (!Number.isSafeInteger(eventId) || eventId < 1))) {
          return json({ ok: false, error: "Invalid notice fields" }, 400);
        }
        const result = await env.DB.prepare(`
          INSERT INTO notices (event_id, title, content, published) VALUES (?, ?, ?, ?)
        `).bind(eventId, title, content, asFlag(body.published)).run();
        return json({ ok: true, id: result.meta.last_row_id }, 201);
      }

      const noticeMatch = path.match(/^\/api\/admin\/notices\/(\d+)$/);
      if (noticeMatch && method === "PUT") {
        const id = Number(noticeMatch[1]);
        let body;
        try { body = await request.json(); } catch {
          return json({ ok: false, error: "Invalid JSON" }, 400);
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ ok: false, error: "Invalid request body" }, 400);
        }
        const title = optionalText(body.title, 200);
        const content = optionalText(body.content, 10000);
        const eventId = body.event_id == null || body.event_id === "" ? null : Number(body.event_id);
        if (!title || !content || (body.event_id != null && body.event_id !== "" && (!Number.isSafeInteger(eventId) || eventId < 1))) {
          return json({ ok: false, error: "Invalid notice fields" }, 400);
        }
        const result = await env.DB.prepare(`
          UPDATE notices SET event_id = ?, title = ?, content = ?, published = ? WHERE id = ?
        `).bind(eventId, title, content, asFlag(body.published), id).run();
        if (!result.meta.changes) return json({ ok: false, error: "Notice not found" }, 404);
        return json({ ok: true });
      }

      if (noticeMatch && method === "DELETE") {
        const result = await env.DB.prepare("DELETE FROM notices WHERE id = ?")
          .bind(Number(noticeMatch[1])).run();
        if (!result.meta.changes) return json({ ok: false, error: "Notice not found" }, 404);
        return json({ ok: true });
      }
      // 관리자 참가자 관리 API
      // 신청자 전체 조회 (입금 여부와 관계없이 조회)
      if (path === "/api/admin/participants" && method === "GET") {
        const eventId = url.searchParams.get("event_id");

        if (!eventId || !/^\d+$/.test(eventId)) {
          return json({
            ok: false,
            error: "Valid event_id is required"
          }, 400);
        }

        const result = await env.DB.prepare(`
          SELECT
            id, event_id, name, affiliation, birth_date, age,
            gender, belt, weight_class, coach, absolute,
            phone, depositor_name,
            dobok_participation, nogi_participation,
            age_division, nogi_level, dobok_weight, nogi_weight,
            dobok_absolute_participation, dobok_absolute_division,
            nogi_absolute_participation, nogi_absolute_division,
            strongest_participation, price_type,
            division_price, absolute_price,
            dobok_absolute_price, nogi_absolute_price,
            strongest_price, nogi_additional, total_price,
            consent1, consent2, consent3,
            registered_at, payment_status
          FROM participants
          WHERE event_id = ?
          ORDER BY id DESC
        `).bind(Number(eventId)).all();

        return json({
          ok: true,
          participants: result.results
        });
      }

      // 참가자 정보 수정 및 입금 확인
      const adminParticipantMatch =
        path.match(/^\/api\/admin\/participants\/(\d+)$/);

      if (adminParticipantMatch && method === "PUT") {
        const id = Number(adminParticipantMatch[1]);

        let body;
        try {
          body = await request.json();
        } catch {
          return json({
            ok: false,
            error: "Invalid JSON"
          }, 400);
        }

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({
            ok: false,
            error: "Invalid request body"
          }, 400);
        }

        const name = optionalText(body.name, 100);
        const affiliation = optionalText(body.affiliation, 150);
        const birthDate = optionalText(body.birth_date, 10);
        const gender = optionalText(body.gender, 30);
        const belt = optionalText(body.belt, 30);
        const weightClass = optionalText(body.weight_class, 50);
        const coach = optionalText(body.coach, 100);
        const phone = optionalText(body.phone, 30);
        const depositorName = optionalText(body.depositor_name, 100);

        const dobokParticipation =
          optionalText(body.dobok_participation, 30);
        const nogiParticipation =
          optionalText(body.nogi_participation, 30);
        const ageDivision =
          optionalText(body.age_division, 50);
        const nogiLevel =
          optionalText(body.nogi_level, 50);
        const dobokWeight =
          optionalText(body.dobok_weight, 50);
        const nogiWeight =
          optionalText(body.nogi_weight, 50);
        const dobokAbsoluteParticipation =
          optionalText(body.dobok_absolute_participation, 30);
        const dobokAbsoluteDivision =
          optionalText(body.dobok_absolute_division, 50);
        const nogiAbsoluteParticipation =
          optionalText(body.nogi_absolute_participation, 30);
        const nogiAbsoluteDivision =
          optionalText(body.nogi_absolute_division, 50);
        const strongestParticipation =
          optionalText(body.strongest_participation, 30);

        const paymentStatus = body.payment_status;
        const totalPrice = Number(body.total_price ?? 0);

        const ageRaw = body.age;
        const age = ageRaw === "" || ageRaw == null
          ? null
          : Number(ageRaw);

        const optionalFields = [
          birthDate, gender, belt, weightClass, coach, phone,
          depositorName, dobokParticipation, nogiParticipation,
          ageDivision, nogiLevel, dobokWeight, nogiWeight,
          dobokAbsoluteParticipation, dobokAbsoluteDivision,
          nogiAbsoluteParticipation, nogiAbsoluteDivision,
          strongestParticipation
        ];

        if (
          !name ||
          !affiliation ||
          optionalFields.some(value => value === undefined) ||
          !["pending", "confirmed"].includes(paymentStatus) ||
          !Number.isSafeInteger(totalPrice) ||
          totalPrice < 0 ||
          (age !== null &&
            (!Number.isSafeInteger(age) || age < 0 || age > 120))
        ) {
          return json({
            ok: false,
            error: "Invalid participant fields"
          }, 400);
        }

        const absolute =
          dobokAbsoluteParticipation === "참가" ||
          nogiAbsoluteParticipation === "참가"
            ? 1
            : 0;

        const result = await env.DB.prepare(`
          UPDATE participants SET
            name = ?,
            affiliation = ?,
            birth_date = ?,
            age = ?,
            gender = ?,
            belt = ?,
            weight_class = ?,
            coach = ?,
            absolute = ?,
            phone = ?,
            depositor_name = ?,
            dobok_participation = ?,
            nogi_participation = ?,
            age_division = ?,
            nogi_level = ?,
            dobok_weight = ?,
            nogi_weight = ?,
            dobok_absolute_participation = ?,
            dobok_absolute_division = ?,
            nogi_absolute_participation = ?,
            nogi_absolute_division = ?,
            strongest_participation = ?,
            total_price = ?,
            payment_status = ?
          WHERE id = ?
        `).bind(
          name,
          affiliation,
          birthDate,
          age,
          gender,
          belt,
          weightClass,
          coach,
          absolute,
          phone,
          depositorName,
          dobokParticipation,
          nogiParticipation,
          ageDivision,
          nogiLevel,
          dobokWeight,
          nogiWeight,
          dobokAbsoluteParticipation,
          dobokAbsoluteDivision,
          nogiAbsoluteParticipation,
          nogiAbsoluteDivision,
          strongestParticipation,
          totalPrice,
          paymentStatus,
          id
        ).run();

        if (!result.meta.changes) {
          return json({
            ok: false,
            error: "Participant not found"
          }, 404);
        }

        return json({ ok: true });
      }

      // 참가 신청 삭제
      if (adminParticipantMatch && method === "DELETE") {
        const result = await env.DB.prepare(`
          DELETE FROM participants WHERE id = ?
        `).bind(Number(adminParticipantMatch[1])).run();

        if (!result.meta.changes) {
          return json({
            ok: false,
            error: "Participant not found"
          }, 404);
        }

        return json({ ok: true });
      }
      // 서버 및 DB 연결 확인
      if (path === "/api/health" && method === "GET") {
        const result = await env.DB.prepare("SELECT 1 AS ok").first();

        return json({
          ok: result?.ok === 1,
          service: "MUT Championship API",
          database: result?.ok === 1 ? "connected" : "check required"
        });
      }

      // 공개 랭킹: PC와 모바일에서 동일한 D1 기록 조회
      if (path === "/api/rankings" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, player_name, affiliation, belt, gold, silver, bronze, points
          FROM rankings
          ORDER BY points DESC, gold DESC, silver DESC, bronze DESC, player_name ASC
        `).all();
        return json({ ok: true, rankings: result.results });
      }

      // 대회 일정 조회
      if (path === "/api/events" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, name, event_date, venue, event_time,
                 description, registration_open, participants_public,
                 early_bird_start, early_bird_end,
                 registration_start, registration_end, poster_url, photo_url
          FROM events
          ORDER BY event_date ASC, id DESC
        `).all();

        return json({ ok: true, events: result.results });
      }

      // 공개된 공지사항 조회
      if (path === "/api/notices" && method === "GET") {
        const eventId = url.searchParams.get("event_id");
        let result;

        if (eventId !== null) {
          if (!/^\d+$/.test(eventId)) {
            return json({ error: "Invalid event_id" }, 400);
          }

          result = await env.DB.prepare(`
            SELECT id, event_id, title, content, created_at
            FROM notices
            WHERE published = 1 AND (event_id = ? OR event_id IS NULL)
            ORDER BY id DESC
          `).bind(Number(eventId)).all();
        } else {
          result = await env.DB.prepare(`
            SELECT id, event_id, title, content, created_at
            FROM notices
            WHERE published = 1
            ORDER BY id DESC
          `).all();
        }

        return json({ ok: true, notices: result.results });
      }

      // 공개 설정된 대회의 입금 확인 완료 참가자 조회
      if (path === "/api/participants" && method === "GET") {
        const eventId = url.searchParams.get("event_id");

        if (!eventId || !/^\d+$/.test(eventId)) {
          return json({ error: "Valid event_id is required" }, 400);
        }

        const event = await env.DB.prepare(`
          SELECT participants_public FROM events WHERE id = ?
        `).bind(Number(eventId)).first();

        if (!event) {
          return json({ error: "Event not found" }, 404);
        }

        if (event.participants_public !== 1) {
          return json({ ok: true, public: false, participants: [] });
        }

        const result = await env.DB.prepare(`
          SELECT id, name, affiliation, age, belt, weight_class, coach, absolute
          FROM participants
          WHERE event_id = ? AND payment_status = 'confirmed'
          ORDER BY id DESC
        `).bind(Number(eventId)).all();

        return json({
          ok: true,
          public: true,
          participants: result.results
        });
      }

      // 참가 신청 접수
          // 참가 신청 접수
      if (path === "/api/participants" && method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Invalid JSON body" }, 400);
        }

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return json({ error: "Invalid request body" }, 400);
        }

        const eventId = Number(body.event_id ?? body.eventId);

        const name = typeof body.name === "string"
          ? body.name.trim()
          : "";

        const affiliationValue = body.affiliation ?? body.gym;
        const affiliation = typeof affiliationValue === "string"
          ? affiliationValue.trim()
          : "";

        if (
          !Number.isSafeInteger(eventId) ||
          eventId < 1 ||
          !name ||
          !affiliation ||
          name.length > 100 ||
          affiliation.length > 150
        ) {
          return json({
            error: "Valid event_id, name and affiliation are required"
          }, 400);
        }

        const event = await env.DB
          .prepare(`
            SELECT
              registration_open, early_bird_start, early_bird_end,
              registration_start, registration_end
            FROM events
            WHERE id = ?
          `)
          .bind(eventId)
          .first();

        if (!event) {
          return json({ error: "Event not found" }, 404);
        }

        if (event.registration_open !== 1) {
          return json({ error: "Registration is closed" }, 403);
        }

        const today = new Date().toLocaleDateString("en-CA", {
          timeZone: "Asia/Seoul"
        });

        if (
          event.registration_start &&
          today < event.registration_start
        ) {
          return json({ error: "Registration has not started" }, 403);
        }

        if (
          event.registration_end &&
          today > event.registration_end
        ) {
          return json({ error: "Registration period has ended" }, 403);
        }

        const birthDate = optionalText(
          body.birth_date ?? body.birth,
          10
        );

        const phone = optionalText(body.phone, 30);
        const depositorName = optionalText(
          body.depositor_name ?? body.depositorName ?? body.depositor,
          100
        );

        const gender = optionalText(body.gender, 30);
        const belt = optionalText(body.belt, 30);
        const weightClass = optionalText(
          body.weight_class ?? body.dobokWeight ?? body.weight,
          50
        );
        const coach = optionalText(body.coach, 100);

        const dobokParticipation = optionalText(
          body.dobok_participation ?? body.dobokParticipation,
          30
        );

        const nogiParticipation = optionalText(
          body.nogi_participation ?? body.nogiParticipation,
          30
        );

        const ageDivision = optionalText(
          body.age_division ?? body.ageDivision,
          50
        );

        const nogiLevel = optionalText(
          body.nogi_level ?? body.nogiLevel,
          50
        );

        const dobokWeight = optionalText(
          body.dobok_weight ?? body.dobokWeight,
          50
        );

        const nogiWeight = optionalText(
          body.nogi_weight ?? body.nogiWeight,
          50
        );

        const dobokAbsoluteParticipation = optionalText(
          body.dobok_absolute_participation ??
            body.dobokAbsoluteParticipation,
          30
        );

        const dobokAbsoluteDivision = optionalText(
          body.dobok_absolute_division ??
            body.dobokAbsoluteDivision,
          50
        );

        const nogiAbsoluteParticipation = optionalText(
          body.nogi_absolute_participation ??
            body.nogiAbsoluteParticipation,
          30
        );

        const nogiAbsoluteDivision = optionalText(
          body.nogi_absolute_division ??
            body.nogiAbsoluteDivision,
          50
        );

        const strongestParticipation = optionalText(
          body.strongest_participation ?? body.strongestParticipation,
          30
        );

        const fields = [
          birthDate, phone, depositorName, gender, belt,
          weightClass, coach, dobokParticipation, nogiParticipation,
          ageDivision, nogiLevel, dobokWeight, nogiWeight,
          dobokAbsoluteParticipation, dobokAbsoluteDivision,
          nogiAbsoluteParticipation, nogiAbsoluteDivision,
          strongestParticipation
        ];

        if (fields.some(value => value === undefined)) {
          return json({ error: "Invalid optional field" }, 400);
        }

        const ageRaw = body.age;
        let age = null;

        if (
          ageRaw !== undefined &&
          ageRaw !== null &&
          ageRaw !== "" &&
          /^\d+$/.test(String(ageRaw))
        ) {
          age = Number(ageRaw);
        }

        if (age !== null && (age < 0 || age > 120)) {
          return json({ error: "Invalid age" }, 400);
        }

        const earlyBird =
          !!event.early_bird_start &&
          !!event.early_bird_end &&
          today >= event.early_bird_start &&
          today <= event.early_bird_end;

        const basePrice = earlyBird ? 45000 : 55000;
        const extraPrice = earlyBird ? 20000 : 30000;

        const dobokAbsolute =
          dobokAbsoluteParticipation === "참가";

        const nogiAbsolute =
          nogiAbsoluteParticipation === "참가";

        const strongest =
          strongestParticipation === "참가";

        const nogiAdditional =
          dobokParticipation === "참가" &&
          nogiParticipation === "참가"
            ? extraPrice
            : 0;

        const dobokAbsolutePrice =
          dobokAbsolute ? extraPrice : 0;

        const nogiAbsolutePrice =
          nogiAbsolute ? extraPrice : 0;

        const strongestPrice =
          strongest ? extraPrice : 0;

        const absolutePrice =
          dobokAbsolutePrice + nogiAbsolutePrice;

        const totalPrice =
          basePrice +
          nogiAdditional +
          dobokAbsolutePrice +
          nogiAbsolutePrice +
          strongestPrice;

        const absolute = dobokAbsolute || nogiAbsolute ? 1 : 0;

        const consent1 = asFlag(body.consent1);
        const consent2 = asFlag(body.consent2);
        const consent3 = asFlag(body.consent3);

        const registeredAt = new Date().toISOString();

        const result = await env.DB
          .prepare(`
            INSERT INTO participants (
              event_id, name, affiliation, birth_date, age,
              gender, belt, weight_class, coach, absolute,
              phone, depositor_name,
              dobok_participation, nogi_participation,
              age_division, nogi_level, dobok_weight, nogi_weight,
              dobok_absolute_participation, dobok_absolute_division,
              nogi_absolute_participation, nogi_absolute_division,
              strongest_participation, price_type,
              division_price, absolute_price,
              dobok_absolute_price, nogi_absolute_price,
              strongest_price, nogi_additional, total_price,
              consent1, consent2, consent3, registered_at
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?
            )
          `)
          .bind(
            eventId, name, affiliation, birthDate, age,
            gender, belt, weightClass, coach, absolute,
            phone, depositorName,
            dobokParticipation, nogiParticipation,
            ageDivision, nogiLevel, dobokWeight, nogiWeight,
            dobokAbsoluteParticipation, dobokAbsoluteDivision,
            nogiAbsoluteParticipation, nogiAbsoluteDivision,
            strongestParticipation,
            earlyBird ? "얼리버드" : "일반",
            basePrice, absolutePrice,
            dobokAbsolutePrice, nogiAbsolutePrice,
            strongestPrice, nogiAdditional, totalPrice,
            consent1, consent2, consent3, registeredAt
          )
          .run();

        return json({
          ok: true,
          message: "Application received",
          participant_id: result.meta.last_row_id,
          total_price: totalPrice,
          price_type: earlyBird ? "얼리버드" : "일반"
        }, 201);
      }

      if (path.startsWith("/api/")) {
        return json({ error: "API endpoint not found" }, 404);
      }

      // 기존 홈페이지 파일 제공
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("MUT API error:", error);

      return json({
        ok: false,
        error: "Internal server error"
      }, 500);
    }
  }
};
  

