import PropTypes from 'prop-types';
import React from 'react';

import {t, tct} from '../../../../locale';
import Button from '../../../../components/buttons/button';
import ExternalLink from '../../../../components/externalLink';
import SentryTypes from '../../../../proptypes';

class ProviderItem extends React.PureComponent {
  static propTypes = {
    providerKey: PropTypes.string.isRequired,
    providerName: PropTypes.string.isRequired,
    onConfigure: PropTypes.func.isRequired
  };

  static defaultProps = {
    onConfigure: () => {}
  };

  handleConfigure = e => {
    this.props.onConfigure(this.props.providerKey, e);
  };

  render() {
    let {providerKey, providerName} = this.props;
    return (
      <li key={providerKey}>
        <div className={`provider-logo ${providerName.toLowerCase()}`} />
        <Button onClick={this.handleConfigure} className="pull-right">
          {t('Configure')}
        </Button>
        <h4>{providerName}</h4>
        <p>
          {tct('Enable your organization to sign in with [providerName]', {providerName})}
          .
        </p>
      </li>
    );
  }
}

class OrganizationAuthList extends React.Component {
  static contextTypes = {
    organization: SentryTypes.Organization
  };

  static propTypes = {
    onConfigure: PropTypes.func,
    providerList: PropTypes.arrayOf(PropTypes.arrayOf(PropTypes.string))
  };

  render() {
    let {providerList, onConfigure} = this.props;
    let hasProviderList = providerList && providerList.length;

    return (
      <div className="sso">
        <h2>{t('Authentication')}</h2>

        <div className="box">
          <div className="box-header"><h3>{t('Choose a provider')}</h3></div>
          <div className="box-content with-padding">

            <p>
              {tct(
                `Get started with Single Sign-on for your organization by selecting a 
              provider. For more information on SSO please see our [link:documentation]`,
                {
                  link: <ExternalLink href="https://docs.sentry.io/learn/sso/" />
                }
              )}.
            </p>

            {hasProviderList &&
              <ul className="simple-list list-unstyled">
                {providerList.map(([providerKey, providerName]) => (
                  <ProviderItem
                    key={providerKey}
                    providerKey={providerKey}
                    providerName={providerName}
                    onConfigure={onConfigure}
                  />
                ))}
              </ul>}

            {!hasProviderList &&
              <p style={{padding: 50, textAlign: 'center'}}>
                {t('No authentication providers are available.')}
              </p>}
          </div>
        </div>
      </div>
    );
  }
}

export default OrganizationAuthList;
