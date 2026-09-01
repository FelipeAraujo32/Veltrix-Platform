package br.com.veltrix.auth.interfaces;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import br.com.veltrix.auth.domain.*;
import br.com.veltrix.auth.infrastructure.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/** Fluxos da gestão de equipe: escopo por tenant do JWT, guardas de autoproteção e senha temporária. */
@SpringBootTest
@ActiveProfiles("test")
class TeamControllerTest {
    @Autowired WebApplicationContext context;
    private final ObjectMapper json = new ObjectMapper();
    @Autowired UserRepository users; @Autowired RoleRepository roles; @Autowired PermissionRepository permissions;
    @Autowired RefreshTokenRepository refreshTokens; @Autowired PasswordEncoder passwords; @Autowired JwtService jwt;

    private MockMvc mvc;
    private Role adminConta, operadorOuvidoria;
    private User gestoraA, gestorB, operadorA;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        refreshTokens.deleteAll(); users.deleteAll(); roles.deleteAll(); permissions.deleteAll();
        Permission teamManage = permissions.save(new Permission("ACCOUNT_TEAM_MANAGE", true));
        Permission ouvidoriaRead = permissions.save(new Permission("OUVIDORIA_MANIFESTATION_READ", true));
        permissions.save(new Permission("BILLING_SUBSCRIPTION_READ", true));
        permissions.save(new Permission("BILLING_ENTITLEMENT_OVERRIDE")); // plataforma: tenant_assignable=false (default fail-closed)
        permissions.save(new Permission("SENSITIVE_DATA_EXPORT"));
        adminConta = new Role("Admin da Conta"); adminConta.addPermission(teamManage); adminConta = roles.save(adminConta); // tenant_id NULL = template
        operadorOuvidoria = new Role("Operador Ouvidoria"); operadorOuvidoria.addPermission(ouvidoriaRead); operadorOuvidoria = roles.save(operadorOuvidoria);
        gestoraA = user("gestora@tenant-a.com", "Gestora A", "TENANT-A", adminConta);
        gestorB = user("gestor@tenant-b.com", "Gestor B", "TENANT-B", adminConta);
        operadorA = user("operador@tenant-a.com", "Operador A", "TENANT-A", operadorOuvidoria);
    }

    private User user(String email, String name, String tenant, Role role) {
        User created = new User(email, passwords.encode("SenhaInicial-123"), name, UserStatus.ACTIVE);
        created.changeAccessContext(tenant, null); created.addRole(role);
        return users.save(created);
    }

    private String bearer(User user) { return "Bearer " + jwt.create(user); }

    // --- POST /users ---

    @Test
    void criaUsuarioComSenhaTemporariaNoTenantDoGestor() throws Exception {
        var response = mvc.perform(post("/api/v1/team/users").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nova@tenant-a.com\",\"name\":\"Nova Colaboradora\",\"roleIds\":[%d]}".formatted(operadorOuvidoria.getId())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("nova@tenant-a.com"))
                .andReturn().getResponse().getContentAsString();
        JsonNode body = json.readTree(response);
        String temporaryPassword = body.get("temporaryPassword").asText();
        assertThat(temporaryPassword.length()).isGreaterThanOrEqualTo(16);
        User created = users.findByEmailIgnoreCase("nova@tenant-a.com").orElseThrow();
        assertThat(created.getTenantId()).isEqualTo("TENANT-A");
        assertThat(created.isPasswordChangeRequired()).isTrue();
        assertThat(created.getRoles()).extracting(Role::getName).containsExactly("Operador Ouvidoria");
        assertThat(passwords.matches(temporaryPassword, created.getPasswordHash())).isTrue();
    }

    @Test
    void rejeitaEmailDuplicadoIgnorandoCaixa() throws Exception {
        mvc.perform(post("/api/v1/team/users").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"OPERADOR@tenant-a.com\",\"name\":\"Duplicada\",\"roleIds\":[%d]}".formatted(operadorOuvidoria.getId())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("EMAIL_IN_USE"));
    }

    @Test
    void rejeitaPerfilCustomDeOutroTenantAoCriarUsuario() throws Exception {
        Role customA = roles.save(new Role("Suporte A", "TENANT-A"));
        mvc.perform(post("/api/v1/team/users").header("Authorization", bearer(gestorB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"novo@tenant-b.com\",\"name\":\"Novo\",\"roleIds\":[%d]}".formatted(customA.getId())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ROLE_NOT_FOUND"));
    }

    // --- GET /users ---

    @Test
    void listaApenasUsuariosDoTenantDoChamador() throws Exception {
        mvc.perform(get("/api/v1/team/users").header("Authorization", bearer(gestoraA)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[*].email").value(org.hamcrest.Matchers.containsInAnyOrder("gestora@tenant-a.com", "operador@tenant-a.com")))
                .andExpect(jsonPath("$[0].passwordChangeRequired").value(false));
    }

    @Test
    void negaAcessoSemPermissaoDeGestaoDeEquipe() throws Exception {
        mvc.perform(get("/api/v1/team/users").header("Authorization", bearer(operadorA)))
                .andExpect(status().isForbidden());
    }

    // --- PATCH /users/{id} ---

    @Test
    void usuarioDeOutroTenantRetorna404SemVazarExistencia() throws Exception {
        mvc.perform(patch("/api/v1/team/users/" + operadorA.getId()).header("Authorization", bearer(gestorB))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INACTIVE\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("USER_NOT_FOUND"));
        mvc.perform(post("/api/v1/team/users/" + operadorA.getId() + "/reset-password").header("Authorization", bearer(gestorB)))
                .andExpect(status().isNotFound());
        assertThat(users.findById(operadorA.getId()).orElseThrow().getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void bloqueiaAutoDesativacao() throws Exception {
        mvc.perform(patch("/api/v1/team/users/" + gestoraA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INACTIVE\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("SELF_DEACTIVATION"));
        assertThat(users.findById(gestoraA.getId()).orElseThrow().getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void bloqueiaRemocaoDaPropriaPermissaoDeGestao() throws Exception {
        mvc.perform(patch("/api/v1/team/users/" + gestoraA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleIds\":[%d]}".formatted(operadorOuvidoria.getId())))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("SELF_TEAM_MANAGE_REMOVAL"));
    }

    @Test
    void atualizaPerfisEStatusDeOutroUsuario() throws Exception {
        mvc.perform(patch("/api/v1/team/users/" + operadorA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roleIds\":[%d],\"status\":\"INACTIVE\"}".formatted(adminConta.getId())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INACTIVE"))
                .andExpect(jsonPath("$.roles[0].name").value("Admin da Conta"));
        User updated = users.findById(operadorA.getId()).orElseThrow();
        assertThat(updated.getStatus()).isEqualTo(UserStatus.INACTIVE);
        assertThat(updated.getRoles()).extracting(Role::getName).containsExactly("Admin da Conta");
    }

    // --- roles ---

    @Test
    void listaTemplatesEPerfisCustomSomenteDoTenant() throws Exception {
        roles.save(new Role("Suporte A", "TENANT-A"));
        roles.save(new Role("Suporte B", "TENANT-B"));
        // Ordenação do controller: templates primeiro, depois por nome.
        mvc.perform(get("/api/v1/team/roles").header("Authorization", bearer(gestoraA)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].name").value(org.hamcrest.Matchers.contains("Admin da Conta", "Operador Ouvidoria", "Suporte A")))
                .andExpect(jsonPath("$[0].template").value(true))
                .andExpect(jsonPath("$[0].permissions[0]").value("ACCOUNT_TEAM_MANAGE"))
                .andExpect(jsonPath("$[2].template").value(false));
    }

    @Test
    void criaEAtualizaPerfilCustomDoTenant() throws Exception {
        var response = mvc.perform(post("/api/v1/team/roles").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Suporte N1\",\"permissionNames\":[\"OUVIDORIA_MANIFESTATION_READ\"]}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.template").value(false))
                .andReturn().getResponse().getContentAsString();
        long roleId = json.readTree(response).get("id").asLong();
        mvc.perform(patch("/api/v1/team/roles/" + roleId).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Suporte N2\",\"permissionNames\":[\"OUVIDORIA_MANIFESTATION_READ\",\"BILLING_SUBSCRIPTION_READ\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Suporte N2"))
                .andExpect(jsonPath("$.permissions.length()").value(2));
        Role updated = roles.findById(roleId).orElseThrow();
        assertThat(updated.getTenantId()).isEqualTo("TENANT-A");
        assertThat(updated.getPermissions()).extracting(Permission::getName)
                .containsExactlyInAnyOrder("OUVIDORIA_MANIFESTATION_READ", "BILLING_SUBSCRIPTION_READ");
    }

    @Test
    void rejeitaNomeDePerfilJaVisivelAoTenant() throws Exception {
        mvc.perform(post("/api/v1/team/roles").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"admin da conta\",\"permissionNames\":[\"OUVIDORIA_MANIFESTATION_READ\"]}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ROLE_NAME_IN_USE"));
    }

    @Test
    void perfilTemplateESomenteLeitura() throws Exception {
        mvc.perform(patch("/api/v1/team/roles/" + adminConta.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Hackeado\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("TEMPLATE_ROLE_READONLY"));
        assertThat(roles.findById(adminConta.getId()).orElseThrow().getName()).isEqualTo("Admin da Conta");
    }

    @Test
    void perfilCustomDeOutroTenantRetorna404() throws Exception {
        Role customA = roles.save(new Role("Suporte A", "TENANT-A"));
        mvc.perform(patch("/api/v1/team/roles/" + customA.getId()).header("Authorization", bearer(gestorB))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Invadido\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ROLE_NOT_FOUND"));
    }

    @Test
    void rejeitaPermissaoInexistente() throws Exception {
        mvc.perform(post("/api/v1/team/roles").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Suporte\",\"permissionNames\":[\"NAO_EXISTE\"]}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("PERMISSION_NOT_FOUND"));
    }

    // --- GET /permissions ---

    @Test
    void expoeApenasPermissoesAtribuiveisPeloTenant() throws Exception {
        // As de plataforma (BILLING_ENTITLEMENT_OVERRIDE, SENSITIVE_DATA_EXPORT) nem aparecem no catálogo.
        mvc.perform(get("/api/v1/team/permissions").header("Authorization", bearer(gestoraA)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(org.hamcrest.Matchers.containsInAnyOrder(
                        "ACCOUNT_TEAM_MANAGE", "BILLING_SUBSCRIPTION_READ", "OUVIDORIA_MANIFESTATION_READ")))
                .andExpect(jsonPath("$").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem("BILLING_ENTITLEMENT_OVERRIDE"))));
    }

    // --- escopo de permissão (PLATFORM vs TENANT) ---

    @Test
    void rejeitaPermissaoDePlataformaAoCriarPerfil() throws Exception {
        mvc.perform(post("/api/v1/team/roles").header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Escalada\",\"permissionNames\":[\"OUVIDORIA_MANIFESTATION_READ\",\"BILLING_ENTITLEMENT_OVERRIDE\"]}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("PERMISSION_NOT_ASSIGNABLE"));
        assertThat(roles.findByNameAndTenantId("Escalada", "TENANT-A")).isEmpty();
    }

    @Test
    void rejeitaPermissaoDePlataformaAoAtualizarPerfil() throws Exception {
        Role customA = roles.save(new Role("Suporte A", "TENANT-A"));
        mvc.perform(patch("/api/v1/team/roles/" + customA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permissionNames\":[\"SENSITIVE_DATA_EXPORT\"]}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("PERMISSION_NOT_ASSIGNABLE"));
        assertThat(roles.findById(customA.getId()).orElseThrow().getPermissions()).isEmpty();
    }

    @Test
    void bloqueiaNomeDePerfilReservado() throws Exception {
        for (String reserved : new String[]{"ADMIN", "admin", " Admin "}) {
            mvc.perform(post("/api/v1/team/roles").header("Authorization", bearer(gestoraA))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"%s\",\"permissionNames\":[\"OUVIDORIA_MANIFESTATION_READ\"]}".formatted(reserved)))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error").value("ROLE_NAME_RESERVED"));
        }
        Role customA = roles.save(new Role("Suporte A", "TENANT-A"));
        mvc.perform(patch("/api/v1/team/roles/" + customA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Admin\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("ROLE_NAME_RESERVED"));
    }

    // --- fluxo de senha temporária + troca de senha ---

    @Test
    void resetEmiteSenhaTemporariaETrocaLimpaObrigatoriedade() throws Exception {
        var response = mvc.perform(post("/api/v1/team/users/" + operadorA.getId() + "/reset-password")
                        .header("Authorization", bearer(gestoraA)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String temporaryPassword = json.readTree(response).get("temporaryPassword").asText();
        assertThat(temporaryPassword.length()).isGreaterThanOrEqualTo(16);
        User afterReset = users.findById(operadorA.getId()).orElseThrow();
        long versionAfterReset = afterReset.getTokenVersion();
        assertThat(afterReset.isPasswordChangeRequired()).isTrue();
        assertThat(passwords.matches(temporaryPassword, afterReset.getPasswordHash())).isTrue();

        mvc.perform(post("/api/v1/me/password").header("Authorization", bearer(operadorA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"%s\",\"newPassword\":\"MinhaNovaSenha-123\"}".formatted(temporaryPassword)))
                .andExpect(status().isNoContent());
        User afterChange = users.findById(operadorA.getId()).orElseThrow();
        assertThat(afterChange.isPasswordChangeRequired()).isFalse();
        assertThat(afterChange.getTokenVersion()).isGreaterThan(versionAfterReset);
        assertThat(passwords.matches("MinhaNovaSenha-123", afterChange.getPasswordHash())).isTrue();
    }

    // --- revogação de sessão (refresh tokens) ---

    private String activeRefreshToken(User user) {
        String raw = "refresh-" + user.getId() + "-" + System.nanoTime();
        refreshTokens.save(new RefreshToken(AuthController.hash(raw), user, java.time.Instant.now().plusSeconds(3600)));
        return raw;
    }

    private boolean refreshTokenStillValid(String raw) {
        return refreshTokens.findByTokenHash(AuthController.hash(raw)).orElseThrow().isValid(java.time.Instant.now());
    }

    @Test
    void resetDeSenhaRevogaRefreshTokensDoUsuario() throws Exception {
        String raw = activeRefreshToken(operadorA);
        mvc.perform(post("/api/v1/team/users/" + operadorA.getId() + "/reset-password").header("Authorization", bearer(gestoraA)))
                .andExpect(status().isOk());
        assertThat(refreshTokenStillValid(raw)).isFalse();
        // Fim a fim: mesmo com usuário ainda ATIVO, o refresh antigo não renova sessão.
        mvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("veltrix_refresh", raw), new Cookie("veltrix_csrf", "token-teste"))
                        .header("X-CSRF-Token", "token-teste"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void desativacaoRevogaRefreshTokensDoUsuario() throws Exception {
        String raw = activeRefreshToken(operadorA);
        mvc.perform(patch("/api/v1/team/users/" + operadorA.getId()).header("Authorization", bearer(gestoraA))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INACTIVE\"}"))
                .andExpect(status().isOk());
        assertThat(refreshTokenStillValid(raw)).isFalse();
    }

    @Test
    void trocaDeSenhaRevogaRefreshTokensDoUsuario() throws Exception {
        String raw = activeRefreshToken(operadorA);
        mvc.perform(post("/api/v1/me/password").header("Authorization", bearer(operadorA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"SenhaInicial-123\",\"newPassword\":\"MinhaNovaSenha-123\"}"))
                .andExpect(status().isNoContent());
        assertThat(refreshTokenStillValid(raw)).isFalse();
    }

    @Test
    void trocaDeSenhaExigeSenhaAtualCorreta() throws Exception {
        mvc.perform(post("/api/v1/me/password").header("Authorization", bearer(operadorA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"errada-total\",\"newPassword\":\"MinhaNovaSenha-123\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("INVALID_CURRENT_PASSWORD"));
    }

    @Test
    void trocaDeSenhaRejeitaSenhaFraca() throws Exception {
        mvc.perform(post("/api/v1/me/password").header("Authorization", bearer(operadorA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"SenhaInicial-123\",\"newPassword\":\"curta1\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
    }

    // --- login e /me expõem passwordChangeRequired ---

    @Test
    void loginEMeExpoemObrigatoriedadeDeTrocaDeSenha() throws Exception {
        User pendente = new User("pendente@tenant-a.com", passwords.encode("SenhaInicial-123"), "Pendente", UserStatus.ACTIVE);
        pendente.changeAccessContext("TENANT-A", null); pendente.requirePasswordChange(); users.save(pendente);
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .cookie(new Cookie("veltrix_csrf", "token-teste")).header("X-CSRF-Token", "token-teste")
                        .content("{\"email\":\"pendente@tenant-a.com\",\"password\":\"SenhaInicial-123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passwordChangeRequired").value(true));
        mvc.perform(get("/api/v1/me").header("Authorization", bearer(pendente)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passwordChangeRequired").value(true));
    }
}
