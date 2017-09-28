from __future__ import absolute_import

from rest_framework import serializers, status
from rest_framework.response import Response

from sentry.api.bases.organization import OrganizationEndpoint, OrganizationApiKeysPermission
from sentry.api.exceptions import ResourceDoesNotExist
from sentry.api.serializers import serialize
from sentry.models import ApiKey, AuditLogEntryEvent


class ApiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiKey
        fields = ('label', 'scope_list', 'allowed_origins')


class OrganizationApiKeyDetailsEndpoint(OrganizationEndpoint):
    permission_classes = (OrganizationApiKeysPermission, )

    def get(self, request, organization, api_key_id):
        try:
            apikey = ApiKey.objects.get(id=api_key_id,
                                        organization_id=organization.id,
                                        )
        except ApiKey.DoesNotExist:
            raise ResourceDoesNotExist

        return Response(serialize(apikey, request.user))

    def put(self, request, organization, api_key_id):
        """
        Update an API Key
        `````````````

        :pparam string organization_slug: the slug of the organization the
                                          team belongs to.
        :pparam string api_key_id: the api key id
        :param string label: the new label for the api key
        :param array scope_list: an array of scopes available for api key
        :param string allowed_origins: list of allowed origins
        :auth: required
        """
        api_key = ApiKey.objects.get(
            id=api_key_id,
            organization_id=organization.id,
        )

        serializer = ApiKeySerializer(api_key, data=request.DATA, partial=True)
        if serializer.is_valid():
            api_key = serializer.save()

            self.create_audit_entry(
                request=request,
                organization=organization,
                target_object=api_key_id,
                event=AuditLogEntryEvent.APIKEY_EDIT,
                data=api_key.get_audit_log_data(),
            )

            return Response(serialize(api_key, request.user))

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, organization, api_key_id):
        if not request.user.is_authenticated():
            return Response(status=401)

        try:
            key = ApiKey.objects.get(
                id=api_key_id,
                organization_id=organization.id,
            )
        except ApiKey.DoesNotExist:
            pass

        audit_data = key.get_audit_log_data()

        key.delete()

        self.create_audit_entry(
            request,
            organization=organization,
            target_object=key.id,
            event=AuditLogEntryEvent.APIKEY_REMOVE,
            data=audit_data,
        )

        return Response(serialize(key, request.user), status=202)
