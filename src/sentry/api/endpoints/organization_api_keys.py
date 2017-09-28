from __future__ import absolute_import

from rest_framework import serializers, status
from rest_framework.response import Response

from sentry.api.bases.organization import OrganizationEndpoint, OrganizationApiKeysPermission
from sentry.api.serializers import serialize
from sentry.models import ApiKey, AuditLogEntryEvent

DEFAULT_SCOPES = [
    'project:read',
    'event:read',
    'team:read',
    'org:read',
    'member:read',
]


class ApiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiKey
        fields = ('organization', 'scope_list', 'id')


class OrganizationApiKeysEndpoint(OrganizationEndpoint):
    permission_classes = (OrganizationApiKeysPermission, )

    def get(self, request, organization):
        """
        List an Organization's API Keys
        ```````````````````````````````````

        :pparam string organization_slug: the organization short name
        :auth: required
        """
        queryset = sorted(
            ApiKey.objects.filter(
                organization=organization,
            ), key=lambda x: x.label
        )

        return Response(serialize(queryset, request.user))

    def post(self, request, organization):
        if not request.user.is_authenticated():
            return Response(status=401)

        key = ApiKey.objects.create(
            organization=organization,
            scope_list=DEFAULT_SCOPES,
        )

        serializer = ApiKeySerializer(key)

        # Check serializer.is_valid()?
        self.create_audit_entry(
            request,
            organization=organization,
            target_object=key.id,
            event=AuditLogEntryEvent.APIKEY_ADD,
            data=key.get_audit_log_data(),
        )

        return Response(serialize(key, request.user))

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
