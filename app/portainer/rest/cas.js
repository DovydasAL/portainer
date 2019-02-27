angular.module('portainer.app')
.factory('CAS', ['$resource', 'API_ENDPOINT_CAS', function CASFactory($resource, API_ENDPOINT_CAS) {
  'use strict';
  return $resource(API_ENDPOINT_CAS, {}, {
    login: {
      method: 'POST', ignoreLoadingBar: true
    }
  });
}]);