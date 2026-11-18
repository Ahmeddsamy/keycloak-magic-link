<#-- Fallback page for ext-phone-otp; the Parcelo Keycloakify theme overrides it. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('phone'); section>
    <#if section = "title">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <p>${msg("enterPhoneNumber")}</p>
        <form id="kc-phone-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="country" class="${properties.kcLabelClass!}">${msg("phoneCountryLabel")}</label>
                <select id="country" name="country" class="${properties.kcInputClass!}">
                    <#list (allowedCountries![]) as c>
                        <option value="${c}" <#if c == (selectedCountry!'')>selected</#if>>${c}</option>
                    </#list>
                </select>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <label for="phone" class="${properties.kcLabelClass!}">${msg("phoneNumberLabel")}</label>
                <input id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel-national" dir="ltr"
                       value="${(phoneInput!'')}" autofocus class="${properties.kcInputClass!}"
                       aria-invalid="<#if messagesPerField.existsError('phone')>true</#if>"/>
                <#if messagesPerField.existsError('phone')>
                    <span id="input-error-phone" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">${kcSanitize(messagesPerField.get('phone'))?no_esc}</span>
                </#if>
            </div>
            <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                       name="submit" id="kc-submit" type="submit" value="${msg("phoneOtpGetStarted")}"/>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
