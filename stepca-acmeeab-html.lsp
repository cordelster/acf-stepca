<% local view, viewlibrary, page_info = ... %>
<% html = require("acf.html") %>

<h1>ACME EAB Key Management<% if view.acme_prov then %> &mdash; <%= html.html_escape(view.acme_prov.value) %><% end %></h1>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong>
	<pre style="background: transparent; border: none; padding: 0; margin-top: 8px; color: inherit; white-space: pre-wrap;"><%= html.html_escape(view.error.value) %></pre>
</div>
<div class="form-group">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisioners") %>" class="btn btn-default">Back to Provisioners</a>
</div>
<% else %>

<% if view.removed_key then %>
<div class="alert alert-success">
	<strong>EAB key removed:</strong> <code><%= html.html_escape(view.removed_key.value) %></code>
</div>
<% end %>

<!-- Directory URL panel - always shown -->
<% if view.directory_url and view.directory_url.value ~= "" then %>
<div class="panel panel-info">
	<div class="panel-heading">
		<h3 class="panel-title">ACME Directory URL</h3>
	</div>
	<div class="panel-body">
		<p>Configure ACME clients to use this URL:</p>
		<div class="input-group" style="max-width: 700px;">
			<input type="text" id="dir-url" class="form-control" value="<%= html.html_escape(view.directory_url.value) %>" readonly style="font-family: monospace;">
			<span class="input-group-btn">
				<button class="btn btn-default" type="button" onclick="copyField('dir-url')">Copy</button>
			</span>
		</div>
		<p style="margin-top: 15px;"><strong>Quick test</strong> (run on a host that can reach this CA):</p>
		<pre style="background:#f8f8f8; border:1px solid #ddd; padding:10px; border-radius:4px;">step ca certificate myhost.local myhost.crt myhost.key \
  --provisioner <%= html.html_escape(view.acme_prov and view.acme_prov.value or "PROVISIONER") %> \
  --acme <%= html.html_escape(view.directory_url.value) %> \
  --san myhost.local \
  --standalone</pre>
		<small class="text-muted">Note: <code>--standalone</code> uses http-01. Port 80 must be open on the requesting host.</small>
	</div>
</div>
<% end %>

<!-- Credential form - used for listing keys and authorizing add/remove -->
<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Admin Credentials</h3>
	</div>
	<div class="panel-body">
		<p>EAB key operations use the admin API. Provide your JWK provisioner credentials to authenticate.</p>
		<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/acmeeab") %>">
			<div class="form-group">
				<label>ACME Provisioner</label>
				<select name="acme_prov" class="form-control" style="max-width: 300px;">
					<% if view.acme_prov and view.acme_prov.option then %>
					<% for _, opt in ipairs(view.acme_prov.option) do %>
					<option value="<%= html.html_escape(opt) %>"<% if opt == view.acme_prov.value then %> selected<% end %>><%= html.html_escape(opt) %></option>
					<% end %>
					<% else %>
					<option value="<%= html.html_escape(view.acme_prov and view.acme_prov.value or "") %>"><%= html.html_escape(view.acme_prov and view.acme_prov.value or "") %></option>
					<% end %>
				</select>
			</div>
			<div class="form-group">
				<label>Admin Provisioner (JWK)</label>
				<select name="admin_prov" class="form-control" style="max-width: 300px;">
					<% if view.admin_prov and view.admin_prov.option then %>
					<% for _, opt in ipairs(view.admin_prov.option) do %>
					<option value="<%= html.html_escape(opt) %>"<% if opt == view.admin_prov.value then %> selected<% end %>><%= html.html_escape(opt) %></option>
					<% end %>
					<% else %>
					<option value="<%= html.html_escape(view.admin_prov and view.admin_prov.value or "") %>"><%= html.html_escape(view.admin_prov and view.admin_prov.value or "") %></option>
					<% end %>
				</select>
			</div>
			<div class="form-group">
				<label>Admin Password</label>
				<input type="password" name="admin_password" class="form-control" style="max-width: 300px;" placeholder="JWK provisioner password">
				<small class="text-muted">Same password shown when the JWK provisioner was created.</small>
			</div>
			<button type="submit" class="btn btn-primary"><i class="icon-refresh"></i> Load Keys</button>
		</form>
	</div>
</div>

<!-- Key list (only rendered when credentials were submitted) -->
<% if view.eab_keys then %>
<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Existing EAB Keys &mdash; <%= html.html_escape(view.acme_prov and view.acme_prov.value or "") %></h3>
	</div>
	<div class="panel-body">
		<% if view.list_error then %>
		<div class="alert alert-danger"><%= html.html_escape(view.list_error.value) %></div>
		<% elseif #view.eab_keys == 0 then %>
		<p class="text-muted">No EAB keys currently issued for this provisioner.</p>
		<% else %>
		<table class="table table-condensed table-hover">
			<thead><tr><th>Key ID</th><th>Bound</th><th>Created</th><th></th></tr></thead>
			<tbody>
			<% for _, key in ipairs(view.eab_keys) do %>
			<tr>
				<td><code><%= html.html_escape(key.id) %></code></td>
				<td><%= html.html_escape(key.bound) %></td>
				<td><%= html.html_escape(key.created) %></td>
				<td>
					<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/removeacmeeab") %>" style="display:inline;"
						onsubmit="return confirm('Remove EAB key <%= html.html_escape(key.id) %>?');">
						<input type="hidden" name="acme_prov" value="<%= html.html_escape(view.acme_prov and view.acme_prov.value or "") %>">
						<input type="hidden" name="key_id" value="<%= html.html_escape(key.id) %>">
						<input type="hidden" name="admin_prov" value="<%= html.html_escape(view.admin_prov_val and view.admin_prov_val.value or "") %>">
						<input type="hidden" name="admin_password" value="<%= html.html_escape(view.admin_password_hidden and view.admin_password_hidden.value or "") %>">
						<input type="hidden" name="ca_url" value="<%= html.html_escape(view.ca_url and view.ca_url.value or "") %>">
						<button type="submit" class="btn btn-danger btn-xs"><i class="icon-trash"></i> Remove</button>
					</form>
				</td>
			</tr>
			<% end %>
			</tbody>
		</table>
		<% end %>

		<!-- Add new EAB key form -->
		<hr>
		<h4>Add New EAB Key</h4>
		<p>Generates a new EAB Key ID and HMAC key pair. <strong>The HMAC key is shown once &mdash; save it immediately.</strong></p>
		<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/addacmeeab") %>">
			<input type="hidden" name="acme_prov" value="<%= html.html_escape(view.acme_prov and view.acme_prov.value or "") %>">
			<input type="hidden" name="admin_prov" value="<%= html.html_escape(view.admin_prov_val and view.admin_prov_val.value or "") %>">
			<input type="hidden" name="admin_password" value="<%= html.html_escape(view.admin_password_hidden and view.admin_password_hidden.value or "") %>">
			<input type="hidden" name="ca_url" value="<%= html.html_escape(view.ca_url and view.ca_url.value or "") %>">
			<input type="hidden" name="directory_url" value="<%= html.html_escape(view.directory_url and view.directory_url.value or "") %>">
			<button type="submit" class="btn btn-success"><i class="icon-plus"></i> Generate New EAB Key</button>
		</form>
	</div>
</div>
<% end %>

<div class="form-group" style="margin-top: 20px;">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisioners") %>" class="btn btn-default">Back to Provisioners</a>
</div>

<script>
function copyField(id) {
	var el = document.getElementById(id);
	el.select(); el.setSelectionRange(0, 99999);
	document.execCommand("copy");
	alert("Copied to clipboard!");
}
</script>

<% end %>
