<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Revoke Certificate</h1>

<div class="alert alert-danger">
	<h4><i class="icon-warning-sign"></i> Warning: Destructive Action</h4>
	<p>Revoking a certificate is <strong>permanent and cannot be undone</strong>. The certificate will be added to the Certificate Revocation List (CRL) and will no longer be trusted.</p>
	<p>Review the certificate details below before proceeding.</p>
</div>

<% if view.success then %>
	<div class="alert alert-success">
		<strong>Success:</strong> <%= html.html_escape(view.success.value) %>
	</div>
	<% if view.log then %>
	<div class="panel panel-default">
		<div class="panel-heading">
			<h3 class="panel-title">Revocation Log</h3>
		</div>
		<div class="panel-body">
			<pre><%= html.html_escape(view.log.value) %></pre>
		</div>
	</div>
	<% end %>
	<div class="form-group">
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/viewcrl") %>"
			class="btn btn-primary">
			<i class="icon-list"></i> View CRL
		</a>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/listcerts") %>"
			class="btn btn-default">
			<i class="icon-arrow-left"></i> Back to Certificate List
		</a>
	</div>
<% elseif view.error then %>
	<div class="alert alert-danger">
		<strong>Error:</strong> <%= html.html_escape(view.error.value) %>
	</div>
	<div class="form-group">
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/listcerts") %>"
			class="btn btn-default">
			<i class="icon-arrow-left"></i> Back to Certificate List
		</a>
	</div>
<% else %>

<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/dorevoke") %>">

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Revocation Form</h3>
	</div>
	<div class="panel-body">
		<% if view.cert_cn then %>
		<div class="alert alert-info">
			<strong>Common Name:</strong> <%= html.html_escape(view.cert_cn.value) %><br>
			<% if view.cert_not_before then %><strong>Valid From:</strong> <%= html.html_escape(view.cert_not_before.value) %><br><% end %>
			<% if view.cert_not_after then %><strong>Valid To:</strong> <%= html.html_escape(view.cert_not_after.value) %><% end %>
		</div>
		<% end %>

		<div class="form-group" style="margin-bottom: 20px;">
			<label for="serial"><%= html.html_escape(view.serial.label) %></label>
			<input type="text" id="serial" name="serial" value="<%= html.html_escape(view.serial.value) %>" size="50" readonly style="background-color: #f5f5f5;">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.serial.descr) %></small>
		</div>

		<div class="form-group" style="margin-bottom: 20px;">
			<label for="reason"><%= html.html_escape(view.reason.label) %></label>
			<select id="reason" name="reason" style="width: auto; max-width: 300px;">
				<% for _, opt in ipairs(view.reason.option) do %>
				<option value="<%= html.html_escape(opt) %>" <%= opt == view.reason.value and "selected" or "" %>><%= html.html_escape(opt) %></option>
				<% end %>
			</select>
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.reason.descr) %></small>
		</div>

		<div class="form-group" style="margin-bottom: 20px;">
			<label for="confirm"><%= html.html_escape(view.confirm.label) %></label>
			<input type="text" id="confirm" name="confirm" value="<%= html.html_escape(view.confirm.value) %>" size="20" placeholder="REVOKE">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.confirm.descr) %></small>
		</div>

		<div class="form-group" style="margin-top: 30px;">
			<button type="submit" class="btn btn-danger">
				<i class="icon-ban-circle"></i> Revoke Certificate
			</button>
			<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/listcerts") %>" class="btn btn-default">
				<i class="icon-remove"></i> Cancel
			</a>
		</div>
	</div>
</div>

</form>

<div class="alert alert-warning">
	<h4>Revocation Reasons Explained:</h4>
	<dl>
		<dt>Unspecified</dt>
		<dd>General revocation without specific reason</dd>

		<dt>Key Compromise</dt>
		<dd>The private key has been compromised or exposed</dd>

		<dt>CA Compromise</dt>
		<dd>The Certificate Authority itself has been compromised</dd>

		<dt>Affiliation Changed</dt>
		<dd>The subject's affiliation with the organization has changed</dd>

		<dt>Superseded</dt>
		<dd>The certificate has been replaced by a new one</dd>

		<dt>Cessation of Operation</dt>
		<dd>The service or entity is no longer operational</dd>
	</dl>
</div>

<% end %>
