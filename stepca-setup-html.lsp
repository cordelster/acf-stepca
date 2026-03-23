<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<% if view.instructions then %>
<div class="alert alert-info">
	<h4>Setup Instructions</h4>
	<pre><%= html.html_escape(view.instructions.value) %></pre>
</div>
<% end %>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong> <%= html.html_escape(view.error.value) %>
</div>
<% end %>

<% if view.success then %>
<div class="alert alert-success">
	<h4><%= html.html_escape(view.success.label) %></h4>
	<p><%= html.html_escape(view.success.value) %></p>
</div>

	<% if view.ca_password then %>
	<div class="alert alert-warning">
		<h4><i class="icon-warning-sign"></i> <%= html.html_escape(view.ca_password.label) %></h4>
		<p><%= html.html_escape(view.ca_password.descr) %></p>
		<div class="form-group">
			<label>CA Master Password (copy this now!):</label>
			<input type="text" class="form-control" readonly value="<%= html.html_escape(view.ca_password.value) %>"
				onclick="this.select();" style="font-family: monospace; font-size: 16px; width: 62%; max-width: 500px;">
		</div>
		<p class="text-danger"><strong>This password will only be shown ONCE!</strong></p>
	</div>
	<% end %>

	<% if view.password_warning then %>
	<div class="alert alert-warning">
		<%= html.html_escape(view.password_warning.value) %>
	</div>
	<% end %>

	<div class="form-group">
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller) %>" class="btn btn-primary">
			Continue to PKI Manager
		</a>
	</div>

<% else %>

<h2>Certificate Authority Setup</h2>

<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/dosetup") %>">

	<fieldset>
		<legend>Basic CA Information</legend>
		<% htmlviewfunctions.displayformitem(view.ca_name) %>
		<% htmlviewfunctions.displayformitem(view.ca_common_name) %>
		<% htmlviewfunctions.displayformitem(view.ca_organization) %>
		<% htmlviewfunctions.displayformitem(view.ca_organizational_unit) %>
	</fieldset>

	<fieldset>
		<legend>Location Information (Optional)</legend>
		<% htmlviewfunctions.displayformitem(view.ca_locality) %>
		<% htmlviewfunctions.displayformitem(view.ca_state) %>
		<% htmlviewfunctions.displayformitem(view.ca_country) %>
		<% htmlviewfunctions.displayformitem(view.ca_email) %>
	</fieldset>

	<fieldset>
		<legend>Certificate Validity Periods</legend>
		<% htmlviewfunctions.displayformitem(view.ca_provisioner) %>
		<% htmlviewfunctions.displayformitem(view.gen_intermediate) %>
		<% htmlviewfunctions.displayformitem(view.intermediate_validity_years) %>
	</fieldset>

	<fieldset>
		<legend>Optional Features</legend>
		<% htmlviewfunctions.displayformitem(view.enable_ssh) %>
	</fieldset>

	<div class="form-group">
		<button type="submit" class="btn btn-primary btn-lg">
			<i class="icon-ok"></i> Initialize Certificate Authority
		</button>
	</div>

	<div class="alert alert-warning">
		<strong>Important:</strong> A secure password will be generated and displayed ONCE. You must save it immediately!
	</div>

</form>

<% end %>
