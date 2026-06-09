<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "title">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <p>${msg("enterPhoneNumber")}</p>
        <form id="kc-phone-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="phone" class="${properties.kcLabelClass!}">${msg("phoneNumberLabel")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel"
                           placeholder="+9665XXXXXXXX" autofocus
                           class="${properties.kcInputClass!}"
                           aria-invalid="<#if messagesPerField.existsError('phone')>true</#if>"/>
                    <#if messagesPerField.existsError('phone')>
                        <span id="input-error-phone" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">${kcSanitize(messagesPerField.get('phone'))?no_esc}</span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="submit" id="kc-submit" type="submit" value="${msg("doSendCode")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
