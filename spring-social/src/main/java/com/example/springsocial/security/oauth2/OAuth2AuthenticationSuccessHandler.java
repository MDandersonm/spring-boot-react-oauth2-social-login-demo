package com.example.springsocial.security.oauth2;

import com.example.springsocial.config.AppProperties;
import com.example.springsocial.exception.BadRequestException;
import com.example.springsocial.security.TokenProvider;
import com.example.springsocial.util.CookieUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static com.example.springsocial.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    //JWT 생성 및 관리를 담당합니다.
    //사용자의 인증 정보를 바탕으로 토큰을 생성하고, 토큰의 유효성을 검증하는 기능을 포함할 수 있습니다.
    private TokenProvider tokenProvider;


    //애플리케이션의 설정 값을 관리하는 클래스입니다.
    //주로 application.yml 또는 application.properties 파일에서 로드된 설정 값을 포함합니다.
    //OAuth2 관련 설정, 예를 들어 허용된 리디렉션 URI 목록 등을 포함할 수 있습니다.
    private AppProperties appProperties;

    //OAuth2 인증 요청을 쿠키를 통해 저장하고 관리하는 역할을 합니다.
    //인증 후에는 관련 쿠키를 제거하여 클린업을 수행합니다.

    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;


    @Autowired
    OAuth2AuthenticationSuccessHandler(TokenProvider tokenProvider, AppProperties appProperties,
                                       HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    //OAuth2 인증이 성공적으로 완료되었을 때 호출되는 메서드입니다.
    //인증 성공 시 수행해야 할 일들을 정의합니다.

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //determineTargetUrl 메서드를 호출하여 사용자를 리디렉션할 최종 URL을 결정합니다.

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
//clearAuthenticationAttributes 메서드를 호출하여 인증 과정에서 사용된 임시 데이터를 정리합니다.
        clearAuthenticationAttributes(request, response);
        //getRedirectStrategy().sendRedirect(request, response, targetUrl)를 통해 사용자를 최종 리디렉션 URL로 보냅니다.
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    //인증 성공 후 사용자를 리디렉션할 최종 URL을 결정합니다.

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
//isAuthorizedRedirectUri 메서드를 통해 허용된 URI인지 확인합니다.
        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        //유효한 리디렉션 URI가 존재하면 이를 사용하고, 그렇지 않으면 기본 타겟 URL (getDefaultTargetUrl())을 사용합니다.
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        String token = tokenProvider.createToken(authentication);

        //UriComponentsBuilder를 사용하여 타겟 URL에 token이라는 쿼리 파라미터로 JWT를 추가합니다.
        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", token)
                .build().toUriString();
    }

    //인증 과정에서 사용된 임시 데이터를 정리하여 보안을 유지합니다.
    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        //httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response)를 호출하여 OAuth2 인증 요청과 관련된 쿠키를 제거합니다.
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    //주어진 리디렉션 URI가 애플리케이션에서 허용된 URI인지 검증합니다.
    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        //appProperties.getOauth2().getAuthorizedRedirectUris()를 통해 애플리케이션 설정에서 허용된 리디렉션 URI 목록을 가져옵니다.
        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
