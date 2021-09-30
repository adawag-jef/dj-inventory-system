from rest_framework import permissions


class UserActionPermission(permissions.BasePermission):
    message = "You don't have permission to perform this action please contact admin."
    # def has_permission(self, request, view):
    #     if request.user.role.title == 'Admin':
    #         return True
    #     permission_str = f'{view.action}-{view.basename}'
    #     if view.action == 'list':
    #         for perm in request.user.role.permissions.all():
    #             if permission_str == perm.title:
    #                 return True
    #     if view.action == 'retrieve':
    #         for perm in request.user.role.permissions.all():
    #             if permission_str == perm.title:
    #                 return True
    #     if view.action == 'create':
    #         for perm in request.user.role.permissions.all():
    #             if permission_str == perm.title:
    #                 return True
    #     if view.action == 'update' or view.action == 'partial_update':
    #         for perm in request.user.role.permissions.all():
    #             if permission_str == perm.title:
    #                 return True
    #     if view.action == 'destroy':
    #         for perm in request.user.role.permissions.all():
    #             if permission_str == perm.title:
    #                 return True

    def has_object_permission(self, request, view, obj):

        if request.user.role.title == 'Admin':
            return True
        permission_str = f'{view.action}-{view.basename}'
        if view.action == 'list':
            for perm in request.user.role.permissions.all():
                if permission_str == perm.title:
                    return True
        if view.action == 'create':
            for perm in request.user.role.permissions.all():
                if permission_str == perm.title:
                    return True
        if view.action == 'retrieve':
            for perm in request.user.role.permissions.all():
                if request.user.pk == obj.user_id:
                    return True
                if permission_str == perm.title:
                    return True
        if view.action == 'update' or view.action == 'partial_update':
            for perm in request.user.role.permissions.all():
                if request.user.pk == obj.user_id:
                    return True
                if permission_str == perm.title:
                    return True
        if view.action == 'destroy':
            for perm in request.user.role.permissions.all():
                if request.user.pk == obj.user_id:
                    return True
                if permission_str == perm.title:
                    return True
