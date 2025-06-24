from django.urls import path

from user_management import views


urlpatterns = [
    path('login', views.UserLoginView.as_view(), name='user_login'),
    path('logout', views.UserLogoutView.as_view(), name='user_logout'),
    path(
        'reset/request',
        views.ResetPasswordRequestView.as_view(),
        name='user_password_reset_request',
    ),
    path(
        'reset/verify',
        views.ResetPasswordVerifyView.as_view(),
        name='user_password_reset_verify',
    ),
    path(
        'reset/confirm',
        views.ResetPasswordConfirmView.as_view(),
        name='user_password_reset_confirm',
    ),
    path(
        'set-password/verify',
        views.SetPasswordVerifyView.as_view(),
        name='user_set_password_verify',
    ),
    path(
        'set-password/confirm',
        views.SetPasswordConfirmView.as_view(),
        name='user_set_password_confirm',
    ),
    path(
        'sign-up',
        views.SignUpView.as_view(),
        name='user_sign_up',
    ),
    path('sign-in/', views.SignInView.as_view(), name='sign-in'),
    path(
        'change-password',
        views.ChangePasswordView.as_view(),
        name='change_password',
    ),
    path(
        'inner/auth',
        views.InnerAuthView.as_view(),
        name='user_inner_auth',
    ),
    path(
        'verify-account/request',
        views.RequestVerifyAccountEmailView.as_view(),
        name='user_verify_account_request',
    ),
    path(
        'verify-account/confirm',
        views.VerifyAccountView.as_view(),
        name='user_verify_account_confirm',
    ),
    path(
        '<str:redirect_type>/redirect/<str:client>/<str:code>',
        views.RedirectView.as_view(),
        name='user_password_reset_redirect',
    ),
    path(
        '<str:redirect_type>/redirect/<str:client>',
        views.RedirectView.as_view(),
        name='learn_more_redirect',
    ),
    path('client', views.ClientView.as_view(), name='client'),
    path(
        'client/<int:client_id>',
        views.ClientView.as_view(),
        name='client_detail_update_list',
    ),
    path('client/<int:client_id>', views.ClientView.as_view(), name='client_delete'),
    path(
        'client-member/<int:member_id>',
        views.ClientView.as_view(),
        name='client_delete',
    ),
    path(
        'client-details/<int:client_id>',
        views.ClientDetailsView.as_view(),
        name='client_detail',
    ),
    path(
        'members',
        views.ClientMembersView.as_view(),
        name='client_members',
    ),
    path(
        'members/<int:member_id>',
        views.ClientMembersView.as_view(),
        name='client_member',
    ),
    path('profile', views.GetUserProfile.as_view(), name='profile'),
    path('update-profile', views.UpdateUserProfile.as_view(), name='update-profile'),
]
