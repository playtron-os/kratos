// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import { gen, MOBILE_URL, website } from "../../../../helpers"

const signupMobilePasskey = (email = gen.email()) => {
  cy.visit(MOBILE_URL + "/Registration")
  cy.get('input[data-testid="traits.email"]').type(email)
  cy.get('input[data-testid="traits.website"]').type(website)
  cy.get('[data-testid="passkey-button"]').click()

  cy.wait(1000)

  cy.get('[data-testid="session-content"]').should("contain", email)
  cy.get('[data-testid="session-token"]').should("not.be.empty")
  return cy.wrap(email)
}

// The RN app stores the session token in localStorage (AsyncStorage on web).
// cy.clearAllCookies() alone does not clear it, so login flows fail with a
// stale token. This helper clears both cookies and localStorage.
const clearMobileSession = () => {
  cy.clearAllCookies()
  cy.window().then((win) => win.localStorage.clear())
}

// Logout via the RN app's logout button which clears the stored session.
const logoutMobile = () => {
  cy.get('*[data-testid="logout"]').click()
  cy.get('input[data-testid="identifier"]').should("exist")
}

context("Mobile Profile", () => {
  describe("Passkey Flows", () => {
    let authenticator: any

    before(() => {
      cy.task("resetCRI", {})
      cy.useConfigProfile("passkey")

      cy.task("sendCRI", {
        query: "WebAuthn.enable",
        opts: {},
      })
        .then(() => {
          cy.task("sendCRI", {
            query: "WebAuthn.addVirtualAuthenticator",
            opts: {
              options: {
                protocol: "ctap2",
                transport: "internal",
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
              },
            },
          })
        })
        .then((result) => {
          authenticator = result
          cy.log("authenticator ID:", authenticator)
        })

      cy.longPrivilegedSessionTime()
    })

    beforeEach(() => {
      clearMobileSession()
      cy.task("sendCRI", {
        query: "WebAuthn.clearCredentials",
        opts: authenticator,
      })
    })

    after(() => {
      cy.task("sendCRI", {
        query: "WebAuthn.removeVirtualAuthenticator",
        opts: authenticator,
      }).then(() => {
        cy.task("resetCRI", {})
      })
    })

    it("should register with passkey", () => {
      const email = gen.email()
      signupMobilePasskey(email)
    })

    it("should login with passkey after registration", () => {
      const email = gen.email()
      signupMobilePasskey(email).then((registeredEmail) => {
        logoutMobile()
        cy.visit(MOBILE_URL + "/Login")

        cy.get('[data-testid="passkey-button"]').click()
        cy.wait(1000)

        cy.get('[data-testid="session-content"]').should(
          "contain",
          registeredEmail,
        )
        cy.get('[data-testid="session-token"]').should("not.be.empty")
      })
    })

    it("should add passkey in settings after password registration", () => {
      const email = gen.email()
      const password = gen.password()

      cy.registerApi({
        email,
        password,
        fields: { "traits.website": website },
      })
      cy.loginMobile({ email, password })
      cy.visit(MOBILE_URL + "/Settings")

      cy.get(
        '*[data-testid="settings-passkey"] [data-testid="passkey-button"]',
      ).click()
      cy.wait(1000)
      cy.expectSettingsSaved()
    })

    it("should not be able to unlink last passkey", () => {
      signupMobilePasskey().then(() => {
        cy.visit(MOBILE_URL + "/Settings")
        // React Native Web renders disabled as aria-disabled on TouchableOpacity
        cy.get('[data-testid^="passkey-remove-"]').should(
          "have.attr",
          "aria-disabled",
          "true",
        )
      })
    })

    it("should be able to link password then remove passkey", () => {
      const email = gen.email()
      const password = gen.password()

      signupMobilePasskey(email).then(() => {
        cy.visit(MOBILE_URL + "/Settings")

        // Add a password
        cy.get(
          '*[data-testid="settings-password"] input[data-testid="password"]',
        )
          .clear()
          .type(password)
        cy.get(
          '*[data-testid="settings-password"] div[data-testid="submit-form"]',
        ).click()
        cy.expectSettingsSaved()

        // Now passkey remove should be enabled
        cy.get('[data-testid^="passkey-remove-"]').should(
          "not.have.attr",
          "aria-disabled",
          "true",
        )
        cy.get('[data-testid^="passkey-remove-"]').click()
        cy.expectSettingsSaved()

        // Logout and login with password
        logoutMobile()
        cy.loginMobile({ email, password })
        cy.get('[data-testid="session-content"]').should("contain", email)
        cy.get('[data-testid="session-token"]').should("not.be.empty")
      })
    })
  })
})
