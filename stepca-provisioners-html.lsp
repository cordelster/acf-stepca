<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Certificate Authority Provisioners</h1>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong> <%= html.html_escape(view.error.value) %>
</div>
<% end %>

<fieldset>
	<legend>Configured Provisioners</legend>

	<% if view.count then %>
	<p>Total Provisioners: <strong><%= html.html_escape(view.count.value) %></strong></p>
	<% end %>

	<% if view.provisioners and #view.provisioners > 0 then %>
	<% for i, prov in ipairs(view.provisioners) do %>
	<div class="form-group" style="margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 4px;">
		<div style="font-size: 24px; margin-bottom: 10px;"><%= prov.icon.value %> <strong><%= html.html_escape(prov.name.value) %></strong></div>
		<div style="margin-bottom: 5px;">
			<strong>Type:</strong> <span class="label label-primary"><%= html.html_escape(prov.type.value) %></span>
		</div>
		<div style="margin-bottom: 10px; color: #666;">
			<%= html.html_escape(prov.description.value) %>
		</div>
		<% if prov.type.value == "ACME" and prov.directory_url and prov.directory_url.value ~= "" then %>
		<div style="margin-bottom: 10px; font-size: 12px; color: #555;">
			<strong>Directory URL:</strong> <code><%= html.html_escape(prov.directory_url.value) %></code>
		</div>
		<% end %>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisionerdetails?prov_name=" .. prov.name.value) %>"
			class="btn btn-default btn-sm"
			style="display: inline-block; padding: 5px 10px; font-size: 12px; color: #333; background-color: #fff; border: 1px solid #ccc; border-radius: 3px; text-decoration: none; margin-right: 5px;">
			<i class="icon-eye-open"></i> View Details
		</a>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisionerclaims?prov_name=" .. prov.name.value) %>"
			class="btn btn-info btn-sm"
			style="display: inline-block; padding: 5px 10px; font-size: 12px; color: #fff; background-color: #5bc0de; border: 1px solid #46b8da; border-radius: 3px; text-decoration: none; margin-right: 5px;">
			<i class="icon-time"></i> Manage Limits
		</a>
		<% if prov.type.value == "JWK" then %>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/gentoken?prov_name=" .. prov.name.value) %>"
			class="btn btn-warning btn-sm"
			style="display: inline-block; padding: 5px 10px; font-size: 12px; color: #fff; background-color: #f0ad4e; border: 1px solid #eea236; border-radius: 3px; text-decoration: none; margin-right: 5px;">
			<i class="icon-ticket"></i> Generate Token
		</a>
		<% end %>
		<% if prov.type.value == "ACME" then %>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/acmeeab?acme_prov=" .. prov.name.value) %>"
			class="btn btn-warning btn-sm"
			style="display: inline-block; padding: 5px 10px; font-size: 12px; color: #fff; background-color: #f0ad4e; border: 1px solid #eea236; border-radius: 3px; text-decoration: none; margin-right: 5px;">
			<i class="icon-key"></i> Manage EAB Keys
		</a>
		<% end %>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/deleteprovisioner?prov_name=" .. prov.name.value) %>"
			class="btn btn-danger btn-sm"
			style="display: inline-block; padding: 5px 10px; font-size: 12px; color: #fff; background-color: #d9534f; border: 1px solid #d43f3a; border-radius: 3px; text-decoration: none;"
			onclick="return confirm('Are you sure you want to delete the provisioner \'<%= html.html_escape(prov.name.value) %>\'?\n\nNote: You must restart step-ca for changes to take effect.');">
			<i class="icon-trash"></i> Delete
		</a>
	</div>
	<% end %>
	<% else %>
	<div class="alert alert-info">
		No provisioners configured. A provisioner is required to issue certificates.
	</div>
	<% end %>
</fieldset>

<fieldset style="margin-top: 30px;">
	<legend>About Provisioners</legend>

	<p>Provisioners control how certificates are requested and issued. Step-ca supports several types:</p>

	<div style="margin: 15px 0;">
		<strong>Available Provisioner Types:</strong>
		<ul style="margin-top: 10px;">
			<li><strong>🔑 JWK (JSON Web Key)</strong> - Password-based authentication using encrypted keys</li>
			<li><strong>🌐 OIDC (OpenID Connect)</strong> - OAuth2/OIDC authentication (Google, Kanidm, Keycloak, etc.)</li>
			<li><strong>🤖 ACME</strong> - Automated certificate management (Let's Encrypt protocol)</li>
			<li><strong>🔐 SSHPOP</strong> - SSH certificate renewal using proof-of-possession</li>
		</ul>
	</div>

	<div style="margin: 15px 0;">
		<strong>Using OIDC for Certificate Issuance:</strong>
		<p style="margin-top: 5px;">Once configured, users can request certificates using:</p>
		<pre>step ca certificate myhost.example.com host.crt host.key --provisioner kanidm</pre>
		<small style="color: #777; font-size: 85%;">This will open a browser for OIDC authentication via Kanidm.</small>
	</div>
</fieldset>

<div class="form-group" style="margin-top: 30px;">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/addprovisioner") %>"
		class="btn btn-primary"
		style="display: inline-block; padding: 6px 12px; font-size: 14px; color: #fff; background-color: #337ab7; border: 1px solid #2e6da4; border-radius: 4px; text-decoration: none;">
		<i class="icon-plus"></i> Add New Provisioner
	</a>
</div>
