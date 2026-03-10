<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Step CA Manager - Dashboard</h1>

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Certificate Authority Status</h3>
	</div>
	<div class="panel-body">
		<table class="table table-condensed">
			<% if view.ca_initialized then %>
			<tr>
				<th width="200">CA Initialized:</th>
				<td>
					<% if view.ca_initialized.value == "true" then %>
						<span class="label label-success">Yes</span>
					<% else %>
						<span class="label label-danger">No</span>
					<% end %>
				</td>
			</tr>
			<% end %>

			<% if view.step_ca_status then %>
			<tr>
				<th>step-ca Service:</th>
				<td>
					<% if view.step_ca_status.value == "running" then %>
						<span class="label label-success">Running</span>
					<% else %>
						<span class="label label-danger">Stopped</span>
					<% end %>
				</td>
			</tr>
			<% end %>

			<% if view.kmip_status then %>
			<tr>
				<th>KMIP Service:</th>
				<td>
					<% if view.kmip_status.value == "running" then %>
						<span class="label label-success">Running</span>
					<% else %>
						<span class="label label-danger">Stopped</span>
					<% end %>
				</td>
			</tr>
			<% end %>

			<% if view.certificate_count then %>
			<tr>
				<th>Total Certificates:</th>
				<td><%= html.html_escape(view.certificate_count.value) %></td>
			</tr>
			<% end %>
		</table>
	</div>
</div>

<% if view.ca_info then %>
<div class="panel panel-info">
	<div class="panel-heading">
		<h3 class="panel-title">Root CA Information</h3>
	</div>
	<div class="panel-body">
		<pre><%= html.html_escape(view.ca_info.value) %></pre>
	</div>
</div>
<% end %>

<% if view.crl_updated then %>
<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">CRL Status</h3>
	</div>
	<div class="panel-body">
		<p>Last Updated: <%= html.html_escape(view.crl_updated.value) %></p>
	</div>
</div>
<% end %>

<% if viewlibrary and viewlibrary.dispatch_component and viewlibrary.check_permission("startstop") then %>
<% viewlibrary.dispatch_component("startstop") %>
<% end %>
