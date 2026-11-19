
package org.owasp.webgoat.container;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.users.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class SecurityNegativeTest {

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private UserRepository userRepository;

  @MockitoBean
  private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc =
        MockMvcBuilders.webAppContextSetup(context)
            .apply(springSecurity())
            .build();
  }

  @Test
  @WithMockUser(username = "regularuser", authorities = "WEBGOAT_USER")
  void regularUserCannotAccessAdminEndpoints() throws Exception {
    mockMvc
        .perform(get("/service/admin/users"))
        .andExpect(status().isForbidden());
  }

  @Test
  void unauthenticatedRequestIsRejected() throws Exception {
    mockMvc
        .perform(
            get("/service/admin/users")
                .header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void registrationRejectsInvalidUsername() throws Exception {
    String invalidUsername = "INVALID_USERNAME_LAB2";

    assertNull(userRepository.findByUsername(invalidUsername));

    mockMvc
        .perform(
            post("/register.mvc")
                .param("username", invalidUsername)
                .param("password", "valid123")
                .param("matchingPassword", "valid123")
                .param("agree", "true"))
        .andExpect(status().isOk())
        .andExpect(view().name("registration"))
        .andExpect(model().attributeHasFieldErrors("userForm", "username"));

    assertNull(userRepository.findByUsername(invalidUsername));
  }

  @Test
  @WithMockUser(username = "regularuser", authorities = "WEBGOAT_USER")
  void internalErrorDoesNotExposeSensitiveDetails() throws Exception {
    String sensitiveMessage = "LAB2_INTERNAL_SECRET_DO_NOT_EXPOSE";

    mockMvc
        .perform(
            get("/error.html")
                .requestAttr(
                    RequestDispatcher.ERROR_STATUS_CODE,
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .requestAttr(
                    RequestDispatcher.ERROR_MESSAGE,
                    sensitiveMessage)
                .requestAttr(
                    RequestDispatcher.ERROR_EXCEPTION,
                    new IllegalStateException(sensitiveMessage))
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.trace").doesNotExist())
        .andExpect(
            content().string(not(containsString(sensitiveMessage))))
        .andExpect(
            content().string(
                not(containsString("java.lang.IllegalStateException"))));
  }
}
