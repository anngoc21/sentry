import React from 'react';
import {mount} from 'enzyme';

import {Client} from 'app/api';
import OrganizationApiKeys from 'app/views/organizationApiKeys';

const childContextTypes = {
  organization: React.PropTypes.object,
  router: React.PropTypes.object,
  location: React.PropTypes.object
};

describe('OrganizationApiKeys', function() {
  beforeEach(function() {
    Client.clearMockResponses();
    Client.addMockResponse({
      url: '/organizations/org-slug/api-keys/',
      method: 'GET',
      body: [TestStubs.ApiKey()]
    });
    Client.addMockResponse({
      url: '/organizations/org-slug/api-keys/1/',
      method: 'GET',
      body: TestStubs.ApiKey()
    });
  });

  it('renders', function() {
    let wrapper = mount(<OrganizationApiKeys params={{orgId: 'org-slug'}} />, {
      context: {
        router: TestStubs.router(),
        organization: TestStubs.Organization(),
        location: TestStubs.location()
      },
      childContextTypes
    });
    expect(wrapper.state('loading')).toBe(false);
    expect(wrapper).toMatchSnapshot();
  });

  it('can delete a key', function() {
    let wrapper = mount(<OrganizationApiKeys params={{orgId: 'org-slug'}} />, {
      context: {
        router: TestStubs.router(),
        organization: TestStubs.Organization(),
        location: TestStubs.location()
      },
      childContextTypes
    });
    OrganizationApiKeys.handleRemove = jest.fn();
    expect(OrganizationApiKeys.handleRemove).not.toHaveBeenCalled();

    // Click remove button
    wrapper.find('.icon-trash').simulate('click');
    wrapper.update();

    // expect a modal
    let modal = wrapper.find('Modal');
    expect(modal.first().prop('show')).toBe(true);

    // TODO
    // wrapper.find('Modal').last().find('Button').last().simulate('click');

    // expect(OrganizationApiKeys.handleRemove).toHaveBeenCalled();
  });
});
