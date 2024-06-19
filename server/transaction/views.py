from drf_spectacular.utils import OpenApiExample, OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions, status


@extend_schema(
    summary='Pay for subscription',
    request=None,
    responses={
        200: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Success'),
        403: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Permission denied'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'msg': 'Success',
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
    ],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    return response.Response({"msg": "Success"}, 200)


@extend_schema(
    summary='List subscriptions',
    request=None,
    responses={
        200: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Success'),
        403: OpenApiResponse(response=OpenApiTypes.OBJECT, description='Permission denied'),
    },
    examples=[
        OpenApiExample(
            'OK',
            value={
                'msg': 'Success',
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
    ],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    return response.Response({"msg": "Success"}, 200)
