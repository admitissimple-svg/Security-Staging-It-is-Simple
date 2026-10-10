import { setFirebaseAdminAuthForTesting } from '../src/serverFirebaseAdmin';
import {
  firebaseAuthMiddleware,
  getVerifiedUserFromRequest,
  extractTrustedRole,
} from '../src/middleware/firebaseAuth';
import type { Request, Response } from 'express';

// Test runner tracking
let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✅ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${testName} ${detail ? `(${detail})` : ''}`);
    failed++;
  }
}

// Mock Response helper
function createMockResponse() {
  const res: any = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: null,
    setHeader(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(data: any) {
      this.body = data;
      return this;
    },
  };
  return res;
}

// Mock Request helper
function createMockRequest(options: {
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: any;
  params?: Record<string, string>;
  user?: any;
} = {}) {
  const req: any = {
    headers: options.headers || {},
    query: options.query || {},
    body: options.body || {},
    params: options.params || {},
    user: options.user,
  };
  return req;
}

// Isolated mock database for testing
interface TestTutor {
  id: string;
  uid?: string;
  email: string;
  name: string;
  role: string;
  approvalStatus: 'approved' | 'pending' | 'rejected';
  isApproved: boolean;
  status: 'approved' | 'pending' | 'rejected';
  approved: boolean;
  [key: string]: any;
}

interface MockDb {
  tutorsList: TestTutor[];
  teachers: any[];
  authUsers: Record<string, any>;
  deletedTutorEmails?: string[];
  deletedTutorIds?: string[];
}

function createTestDb(): MockDb {
  return {
    tutorsList: [
      {
        id: 'tutor-bob-approved',
        uid: 'uid-bob',
        email: 'bob@example.com',
        name: 'Bob Approved Tutor',
        role: 'teacher',
        approvalStatus: 'approved',
        isApproved: true,
        status: 'approved',
        approved: true,
      },
      {
        id: 'tutor-alice-pending',
        uid: 'uid-alice',
        email: 'alice@example.com',
        name: 'Alice Pending Tutor',
        role: 'teacher',
        approvalStatus: 'pending',
        isApproved: false,
        status: 'pending',
        approved: false,
      },
      {
        id: 'tutor-charlie-pending',
        uid: 'uid-charlie',
        email: 'charlie@example.com',
        name: 'Charlie Pending Tutor',
        role: 'teacher',
        approvalStatus: 'pending',
        isApproved: false,
        status: 'pending',
        approved: false,
      },
      {
        id: 'tutor-david-rejected',
        uid: 'uid-david',
        email: 'david@example.com',
        name: 'David Rejected Tutor',
        role: 'teacher',
        approvalStatus: 'rejected',
        isApproved: false,
        status: 'rejected',
        approved: false,
      },
    ],
    teachers: [
      { email: 'adm.itissimple@gmail.com', name: "Admin It's Simple", role: 'admin' },
      { email: 'bob@example.com', name: 'Bob Approved Tutor', role: 'teacher', approvalStatus: 'approved', isApproved: true },
      { email: 'alice@example.com', name: 'Alice Pending Tutor', role: 'teacher', approvalStatus: 'pending', isApproved: false },
      { email: 'charlie@example.com', name: 'Charlie Pending Tutor', role: 'teacher', approvalStatus: 'pending', isApproved: false },
    ],
    authUsers: {
      'adm.itissimple@gmail.com': { uid: 'admin-master-uid', email: 'adm.itissimple@gmail.com', name: "Admin It's Simple", role: 'admin' },
      'alice@example.com': { uid: 'uid-alice', email: 'alice@example.com', name: 'Alice Pending Tutor', role: 'teacher' },
      'bob@example.com': { uid: 'uid-bob', email: 'bob@example.com', name: 'Bob Approved Tutor', role: 'teacher' },
    },
    deletedTutorEmails: [],
    deletedTutorIds: [],
  };
}

// Handlers exactly matching the implementation in serverApp.ts
function createHandlers(db: MockDb) {
  const TRUSTED_ADMIN_EMAILS = new Set(['adm.itissimple@gmail.com', 'admin@itissimple.com']);

  const getTutorsHandler = async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // SECURITY HOTFIX — Native Friends Public API Authorization
    const verifiedUser = await getVerifiedUserFromRequest(req);

    const isServerVerifiedAdmin = verifiedUser?.role === 'admin';
    const verifiedCallerUid = verifiedUser?.uid || '';
    const verifiedCallerEmail = (verifiedUser?.email || '').toLowerCase().trim();

    const isApprovedTutor = (t: any) => {
      return Boolean(
        t.approvalStatus === 'approved' ||
        t.isApproved === true ||
        t.status === 'approved' ||
        t.approved === true
      );
    };

    if (isServerVerifiedAdmin) {
      const adminList = (db.tutorsList || []).filter((t: any) => {
        const tEmail = (t.email || '').toLowerCase().trim();
        const tId = (t.id || '').toLowerCase().trim();
        return !db.deletedTutorEmails?.includes(tEmail) && !db.deletedTutorIds?.includes(tId);
      });
      return res.json(adminList);
    }

    const filteredList = (db.tutorsList || []).filter((t: any) => {
      const tEmail = (t.email || '').toLowerCase().trim();
      const tId = (t.id || '').toLowerCase().trim();
      if (db.deletedTutorEmails?.includes(tEmail) || db.deletedTutorIds?.includes(tId)) {
        return false;
      }

      if (isApprovedTutor(t)) {
        return true;
      }

      if (verifiedUser && verifiedCallerUid) {
        const isOwnByUid = Boolean(t.uid && t.uid === verifiedCallerUid);
        const isOwnById = Boolean(t.id && t.id === verifiedCallerUid);
        const isOwnByEmail = Boolean(verifiedCallerEmail && tEmail && tEmail === verifiedCallerEmail);
        if (isOwnByUid || isOwnById || isOwnByEmail) {
          return true;
        }
      }

      return false;
    });

    return res.json(filteredList);
  };

  const syncAdminClaimsHandler = async (req: Request, res: Response) => {
    const caller = req.user;
    if (!caller || !caller.uid) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required: verified user token missing' });
    }

    const cleanEmail = (caller.email || '').toLowerCase().trim();

    // Rule 1: Caller email must be verified by Firebase Auth
    if (!caller.email_verified) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Access denied: caller email must be verified to synchronize administrative claims',
      });
    }

    // Rule 2: Caller email MUST belong to authoritative administrator email allowlist
    if (!TRUSTED_ADMIN_EMAILS.has(cleanEmail)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Access denied: caller is not an authorized administrator',
      });
    }

    const isTeacherAdmin = (db.teachers || []).some(
      (t: any) => t.role === 'admin' && (t.email || '').toLowerCase().trim() === cleanEmail
    );
    const isAuthUserAdmin =
      db.authUsers &&
      Object.values(db.authUsers).some(
        (u: any) => u.role === 'admin' && (u.email || '').toLowerCase().trim() === cleanEmail
      );

    const isConfirmedAdmin = isTeacherAdmin || isAuthUserAdmin || cleanEmail === 'adm.itissimple@gmail.com';
    if (!isConfirmedAdmin) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Access denied: administrator account is not active or recognized in system records',
      });
    }

    return res.json({ success: true, role: 'admin', uid: caller.uid });
  };

  const registerHandler = async (req: Request, res: Response) => {
    const { email, role = 'student' } = req.body;
    const cleanEmail = (email || '').toLowerCase().trim();
    const requestedRole = (role || 'student').toLowerCase();

    if (requestedRole === 'admin') {
      if (!TRUSTED_ADMIN_EMAILS.has(cleanEmail)) {
        return res.status(403).json({
          error: 'Forbidden: não é permitido registrar contas de administrador para este endereço de e-mail.',
          hasAdminRegistered: true,
        });
      }
      return res.json({ success: true, role: 'admin' });
    }

    return res.json({ success: true, role: requestedRole });
  };

  return { getTutorsHandler, syncAdminClaimsHandler, registerHandler };
}

async function runSecurityTests() {
  console.log('\n======================================================================');
  console.log('=== TESTES DE SEGURANÇA: NATIVE FRIENDS PUBLIC API AUTHORIZATION ===');
  console.log('=== PROJETO: itissimple-security-staging                           ===');
  console.log('======================================================================\n');

  const db = createTestDb();
  const handlers = createHandlers(db);

  // Helper to extract email list from response
  const getEmails = (res: any): string[] => {
    return Array.isArray(res.body) ? res.body.map((t: any) => t.email) : [];
  };

  // -------------------------------------------------------------------------
  // SEÇÃO 1: CATÁLOGO PÚBLICO E TESTES NEGATIVOS CONTRA BYPASS DE QUERY PARAMS
  // -------------------------------------------------------------------------
  console.log('--- 1. Catálogo público sem login ---');
  {
    const req = createMockRequest();
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    assert(res.statusCode === 200, 'GET /api/tutors público retorna 200 OK');
    const emails = getEmails(res);
    assert(emails.includes('bob@example.com'), 'Professor aprovado (Bob) está no catálogo público');
    assert(!emails.includes('alice@example.com'), 'Professor pendente (Alice) NÃO está no catálogo público');
    assert(!emails.includes('charlie@example.com'), 'Professor pendente (Charlie) NÃO está no catálogo público');
    assert(!emails.includes('david@example.com'), 'Professor rejeitado (David) NÃO está no catálogo público');
    assert(res.body.length === 1, 'Exatamente 1 professor aprovado retornado para visitante anônimo');
  }

  console.log('\n--- 2. Testes negativos: Manipulação de query parameters por visitantes anônimos ---');

  // 2.1 Tentativa com ?admin=true
  {
    const req = createMockRequest({ query: { admin: 'true' } });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: ?admin=true NÃO vaza professor pendente (Alice)');
    assert(!emails.includes('charlie@example.com'), 'NEGATIVO: ?admin=true NÃO vaza professor pendente (Charlie)');
    assert(res.body.length === 1, 'NEGATIVO: ?admin=true retorna apenas catálogo aprovado');
  }

  // 2.2 Tentativa com ?includePending=true
  {
    const req = createMockRequest({ query: { includePending: 'true' } });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: ?includePending=true NÃO vaza professor pendente (Alice)');
    assert(!emails.includes('charlie@example.com'), 'NEGATIVO: ?includePending=true NÃO vaza professor pendente (Charlie)');
    assert(res.body.length === 1, 'NEGATIVO: ?includePending=true retorna apenas catálogo aprovado');
  }

  // 2.3 Tentativa com ?role=admin
  {
    const req = createMockRequest({ query: { role: 'admin' } });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: ?role=admin NÃO vaza professor pendente');
    assert(res.body.length === 1, 'NEGATIVO: ?role=admin ignorado com segurança');
  }

  // 2.4 Tentativa com ?email=adm.itissimple@gmail.com
  {
    const req = createMockRequest({ query: { email: 'adm.itissimple@gmail.com' } });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: ?email=adm.itissimple@gmail.com NÃO concede acesso admin');
    assert(res.body.length === 1, 'NEGATIVO: E-mail de admin na query não concede privilégios');
  }

  // 2.5 Tentativa combinada de bypass com múltiplos parâmetros manipulados
  {
    const req = createMockRequest({
      query: {
        admin: 'true',
        includePending: 'true',
        role: 'admin',
        email: 'adm.itissimple@gmail.com',
        uid: 'admin-master-uid',
      },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: Bypass combinado com todos os parâmetros NÃO vaza pendentes');
    assert(!emails.includes('charlie@example.com'), 'NEGATIVO: Bypass combinado NÃO expõe Charlie');
    assert(res.body.length === 1, 'NEGATIVO: Bypass combinado retorna estritamente catálogo aprovado');
  }

  // 2.6 Tentativa de consultar cadastro pendente de terceiro via ?email ou ?uid sem autenticação
  {
    const req = createMockRequest({
      query: {
        email: 'alice@example.com',
        uid: 'uid-alice',
      },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: Visitante não consegue expor Alice pendente via ?email=alice@example.com');
    assert(res.body.length === 1, 'NEGATIVO: Consultas a terceiros sem autenticação não revelam cadastros pendentes');
  }

  // -------------------------------------------------------------------------
  // SEÇÃO 2: USUÁRIO ALUNO AUTENTICADO TENTANDO OBTER PENDENTES
  // -------------------------------------------------------------------------
  console.log('\n--- 3. Aluno autenticado tentando contornar autorização ---');
  {
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'uid-student-1',
        email: 'student@example.com',
        role: 'student',
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({
      headers: { authorization: 'Bearer student-token' },
      query: { admin: 'true', includePending: 'true', role: 'admin' },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(!emails.includes('alice@example.com'), 'NEGATIVO: Aluno autenticado NÃO consegue listar professores pendentes');
    assert(!emails.includes('charlie@example.com'), 'NEGATIVO: Aluno autenticado NÃO tem acesso administrativo');
    assert(res.body.length === 1, 'Aluno autenticado recebe estritamente catálogo público de aprovados');
  }

  // -------------------------------------------------------------------------
  // SEÇÃO 3: PROFESSOR AUTENTICADO CONSULTANDO SEU PRÓPRIO CADASTRO PENDENTE
  // -------------------------------------------------------------------------
  console.log('\n--- 4. Professor autenticado consultando o próprio cadastro pendente (Req 4) ---');
  {
    // Alice está autenticada com seu próprio token
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'uid-alice',
        email: 'alice@example.com',
        role: 'teacher',
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({
      headers: { authorization: 'Bearer alice-token' },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(emails.includes('bob@example.com'), 'Alice recebe o catálogo de professores aprovados (Bob)');
    assert(emails.includes('alice@example.com'), 'Alice visualiza seu PRÓPRIO cadastro pendente com sucesso');
    assert(!emails.includes('charlie@example.com'), 'Alice NÃO tem acesso ao cadastro pendente de terceiros (Charlie)');
    assert(!emails.includes('david@example.com'), 'Alice NÃO tem acesso ao cadastro rejeitado de David');
    assert(res.body.length === 2, 'Alice recebe exatamente: aprovados + seu próprio cadastro');
  }

  console.log('\n--- 5. Isolamento de terceiros: Professor tentando inspecionar outro pendente ---');
  {
    // Alice tenta passar query params apontando para Charlie
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'uid-alice',
        email: 'alice@example.com',
        role: 'teacher',
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({
      headers: { authorization: 'Bearer alice-token' },
      query: { email: 'charlie@example.com', uid: 'uid-charlie', includePending: 'true' },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(emails.includes('alice@example.com'), 'Alice continua vendo seu próprio cadastro');
    assert(!emails.includes('charlie@example.com'), 'NEGATIVO: Alice NÃO consegue expor cadastro pendente de Charlie mesmo com query parameters');
    assert(res.body.length === 2, 'Retorno restrito exclusivamente a aprovados + própria Alice');
  }

  // -------------------------------------------------------------------------
  // SEÇÃO 4: ADMINISTRADOR AUTENTICADO COM CUSTOM CLAIM VERIFICADA
  // -------------------------------------------------------------------------
  console.log('\n--- 6. Administrador autenticado com autorização verificada pelo servidor (Req 2) ---');
  {
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'admin-master-uid',
        email: 'adm.itissimple@gmail.com',
        role: 'admin',
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({
      headers: { authorization: 'Bearer admin-token' },
    });
    const res = createMockResponse();
    await handlers.getTutorsHandler(req, res);

    const emails = getEmails(res);
    assert(emails.includes('bob@example.com'), 'Admin visualiza Bob (aprovado)');
    assert(emails.includes('alice@example.com'), 'Admin visualiza Alice (pendente)');
    assert(emails.includes('charlie@example.com'), 'Admin visualiza Charlie (pendente)');
    assert(emails.includes('david@example.com'), 'Admin visualiza David (rejeitado)');
    assert(res.body.length === 4, 'Admin recebe listagem completa de professores para moderação');
  }

  // -------------------------------------------------------------------------
  // SEÇÃO 5: AUDITORIA DE /api/auth/sync-admin-claims E REGISTRO (Req 6)
  // -------------------------------------------------------------------------
  console.log('\n--- 7. Auditoria de /api/auth/sync-admin-claims (Req 6) ---');

  // 7.1 Sem token
  {
    const req = createMockRequest();
    const res = createMockResponse();
    let nextCalled = false;
    await firebaseAuthMiddleware(req, res, () => { nextCalled = true; });
    assert(res.statusCode === 401, 'POST /sync-admin-claims sem token retorna 401');
  }

  // 7.2 Aluno tentando sync-admin-claims
  {
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'uid-student-1',
        email: 'student@example.com',
        role: 'student',
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({ headers: { authorization: 'Bearer student' } });
    const res = createMockResponse();
    await firebaseAuthMiddleware(req, res, async () => {
      await handlers.syncAdminClaimsHandler(req, res);
    });
    assert(res.statusCode === 403, 'Aluno comum tentando sync-admin-claims retorna 403 Forbidden');
    assert(res.body?.message?.includes('caller is not an authorized administrator'), 'Informa que usuário não é administrador autorizado');
  }

  // 7.3 E-mail não verificado tentando sync-admin-claims
  {
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'uid-spoof',
        email: 'adm.itissimple@gmail.com', // e-mail do admin, mas sem email_verified
        role: 'student',
        email_verified: false,
      }),
    } as any);

    const req = createMockRequest({ headers: { authorization: 'Bearer unverified-email' } });
    const res = createMockResponse();
    await firebaseAuthMiddleware(req, res, async () => {
      await handlers.syncAdminClaimsHandler(req, res);
    });
    assert(res.statusCode === 403, 'E-mail não verificado tentando sync-admin-claims retorna 403');
    assert(res.body?.message?.includes('caller email must be verified'), 'Informa necessidade de e-mail verificado');
  }

  // 7.4 Administrador legítimo com e-mail verificado
  {
    setFirebaseAdminAuthForTesting({
      verifyIdToken: async () => ({
        uid: 'admin-master-uid',
        email: 'adm.itissimple@gmail.com',
        role: 'student', // token ainda sem claim
        email_verified: true,
      }),
    } as any);

    const req = createMockRequest({ headers: { authorization: 'Bearer legitimate-admin' } });
    const res = createMockResponse();
    await firebaseAuthMiddleware(req, res, async () => {
      await handlers.syncAdminClaimsHandler(req, res);
    });
    assert(res.statusCode === 200, 'Administrador legítimo verificado sincroniza com sucesso (200 OK)');
    assert(res.body?.role === 'admin', 'Resposta confirma atribuição da role admin');
  }

  // 7.5 Usuário comum tentando registrar como admin em POST /api/auth/register
  {
    const req = createMockRequest({
      body: {
        name: 'Attacker Admin',
        email: 'attacker@example.com',
        role: 'admin',
      },
    });
    const res = createMockResponse();
    await handlers.registerHandler(req, res);
    assert(res.statusCode === 403, 'Usuário comum tentando registrar como role=admin retorna 403');
    assert(res.body?.error?.includes('não é permitido registrar contas de administrador'), 'Bloqueio estrito de auto-promoção');
  }

  // Limpeza de mocks
  setFirebaseAdminAuthForTesting(null);

  console.log('\n======================================================================');
  console.log(`TOTAL DE TESTES: ${passed + failed}`);
  console.log(`SUCESSO: ${passed}`);
  console.log(`FALHAS: ${failed}`);
  console.log('======================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runSecurityTests().catch((err) => {
  console.error('Erro nos testes de segurança:', err);
  process.exit(1);
});
