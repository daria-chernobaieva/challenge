from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import exceptions as rest_exceptions, response, decorators as rest_decorators, permissions as rest_permissions, status
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from user import serializers, models
import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business"
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }


@extend_schema(
    summary='User Login',
    auth=[],
    request=serializers.LoginSerializer,
    responses={
        200: OpenApiResponse(response=None, description='Successful authentication'),
        400: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Validation errors'),
        401: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Authentication failure'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'email': 'john.doe@test.com',
                'password': 'test_password',
            },
            request_only=True,
        ),
        OpenApiExample(
            'Invalid email',
            value={
                'email': ['Enter a valid email address.'],
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Field may not be blank',
            value={
                'password': ['This field may not be blank.'],
                'email': ['This field may not be blank.'],
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Incorrect email and/or password',
            value={
                'detail': 'Email or Password is incorrect!',
            },
            response_only=True,
            status_codes=[status.HTTP_401_UNAUTHORIZED],
        ),
    ],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed(
        "Email or Password is incorrect!")


@extend_schema(
    summary='User Registration',
    auth=[],
    request=serializers.RegistrationSerializer,
    responses={
        200: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Successful registration'),
        400: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Validation errors'),
        401: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Authentication failure'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'first_name': 'John',
                'last_name': 'Doe',
                'email': 'john.doe@test.com',
                'password': 'test_password',
                'password2': 'test_password',
            },
            request_only=True,
        ),
        OpenApiExample(
            'Success',
            value='Registered!',
            response_only=True,
            status_codes=[status.HTTP_200_OK],
        ),
        OpenApiExample(
            'Invalid email',
            value={
                'email': ['Enter a valid email address.'],
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Max length restriction',
            value={
                'first_name': 'Ensure this field has no more than 50 characters.',
                'last_name': 'Ensure this field has no more than 50 characters.',
                'password': 'Ensure this field has no more than 128 characters.',
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Field may not be blank',
            value={
                'first_name': ['This field may not be blank.'],
                'last_name': ['This field may not be blank.'],
                'email': ['This field may not be blank.'],
                'password': ['This field may not be blank.'],
                'password2': ['This field may not be blank.'],
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Passwords mismatch',
            value={
                'password': 'Passwords do not match!',
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Invalid credentials',
            value={
                'detail': 'Invalid credentials!',
            },
            response_only=True,
            status_codes=[status.HTTP_401_UNAUTHORIZED],
        ),
    ],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@extend_schema(
    summary='User Logout',
    request=None,
    responses={
        200: OpenApiResponse(response=None, description='Successful logout'),
        400: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Validation errors'),
        403: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Permission denied'),
    },
    examples=[
        OpenApiExample(
            'Invalid token',
            value={
                'detail': 'Invalid token',
            },
            response_only=True,
            status_codes=[status.HTTP_400_BAD_REQUEST],
        ),
        OpenApiExample(
            'Permission denied: user is not authenticated',
            value={
                'detail': 'Forbidden',
            },
            response_only=True,
            status_codes=[status.HTTP_403_FORBIDDEN],
        ),
    ],
)
@rest_decorators.api_view(['POST'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):    
    try:
        refreshToken = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"]=None
        
        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                'No valid token found in cookie \'refresh\'')


@extend_schema(
    summary='Token Refresh',
    request=None,
    responses={
        200: CookieTokenRefreshSerializer,
        401: OpenApiResponse(OpenApiTypes.OBJECT, description='Invalid token')
    },
    examples=[
        OpenApiExample(
            'No valid token found',
            value={
                'detail': 'No valid token found in cookie \'refresh\'',
            },
            response_only=True,
            status_codes=[status.HTTP_401_UNAUTHORIZED],
        ),
        OpenApiExample(
            'General token validation error',
            value={
                'detail':'Token is invalid or expired',
            },
            response_only=True,
            status_codes=[status.HTTP_401_UNAUTHORIZED],
        ),
    ],
)
class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@extend_schema(
    summary='User Info',
    description='Get details about current authenticated user',
    responses={
        200: OpenApiResponse(response=serializers.UserSerializer, description='Success'),
        403: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Permission denied'),
        404: OpenApiResponse(response=OpenApiTypes.OBJECT, description='User not found'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'id': 1,
                'email': 'john.doe@test.com',
                'is_staff': True,
                'first_name': 'John',
                'last_name': 'Doe',
            },
            response_only=True,
            status_codes=[status.HTTP_200_OK],
        ),
        OpenApiExample(
            'Permission denied: user is not authenticated',
            value={
                'detail': 'Forbidden',
            },
            response_only=True,
            status_codes=[status.HTTP_403_FORBIDDEN],
        ),
        OpenApiExample(
            'User not found',
            value={
                'detail': 'Not Found',
            },
            response_only=True,
            status_codes=[status.HTTP_404_NOT_FOUND],
        ),
    ],
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@extend_schema(
    summary='User\'s subscriptions list',
    description='Get subscriptions list for current authenticated user',
    responses={
        200: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Success'),
        403: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Permission denied'),
        404: OpenApiResponse(response=OpenApiTypes.OBJECT, description='User not found'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'id': 'subscriptiom_1PNyN4KpmwOo10Ma8B30AN2n',
                'start_date': '2024-06-19',
                'plan': 'price_1PNyN4KpmwOo10Ma8B30AN2n',
            },
            response_only=True,
            status_codes=[status.HTTP_200_OK],
        ),
        OpenApiExample(
            'Permission denied: user is not authenticated',
            value={
                'detail': 'Forbidden',
            },
            response_only=True,
            status_codes=[status.HTTP_403_FORBIDDEN],
        ),
        OpenApiExample(
            'User not found',
            value={
                'detail': 'Not Found',
            },
            response_only=True,
            status_codes=[status.HTTP_404_NOT_FOUND],
        ),
    ],
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append({
                                    "id": _subscription["id"],
                                    "start_date": str(_subscription["start_date"]),
                                    "plan": prices[_subscription["plan"]["id"]]
                                })

    return response.Response({"subscriptions": subscriptions}, 200)
