<#-- Fallback page for ext-phone-otp; the Parcelo Keycloakify theme overrides it. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "title">
        <#if (channel!'sms') == 'whatsapp'>${msg("phoneOtpTitleWhatsapp")}<#else>${msg("phoneOtpTitleSms")}</#if>
    <#elseif section = "form">
        <p>${msg("phoneOtpSentTo", (phoneNumber!''))}</p>
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" dir="ltr"
                       maxlength="${(codeLength!4)?c}" pattern="[0-9]*" autofocus class="${properties.kcInputClass!}"
                       <#if !(codeUsable!true)>disabled</#if>/>
            </div>
            <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                       name="submit" id="kc-submit" type="submit" value="${msg("phoneOtpVerify")}" <#if !(codeUsable!true)>disabled</#if>/>
            </div>
            <p>
                ${msg("phoneOtpNoCode")}
                <#if (resendAvailableInSeconds!0) gt 0>
                    <span>${msg("phoneOtpResendIn", resendAvailableInSeconds?c)}</span>
                <#else>
                    <button type="submit" name="resend" value="true" formnovalidate>${msg("phoneOtpClickToResend")}</button>
                </#if>
            </p>
            <p><button type="submit" name="back" value="true" formnovalidate>${msg("phoneOtpBackToLogin")}</button></p>
        </form>
    </#if>
</@layout.registrationLayout>
