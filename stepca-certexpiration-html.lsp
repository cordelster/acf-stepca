<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Certificate Expiration Tracking</h1>

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Certificates by Expiration</h3>
	</div>
	<div class="panel-body">
		<% if view.count then %>
		<p>Total Certificates: <strong><%= html.html_escape(view.count.value) %></strong></p>
		<% end %>

		<% if view.certificates and #view.certificates > 0 then %>
		<table class="table table-striped">
			<thead>
				<tr>
					<th>Certificate</th>
					<th>Common Name</th>
					<th>Remaining</th>
					<th>Expiration Date</th>
					<th>Status</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
				<% for i, cert in ipairs(view.certificates) do %>
				<tr class="<% if cert.color.value == "red" then %>danger<% elseif cert.color.value == "yellow" then %>warning<% elseif cert.color.value == "green" then %>success<% end %>">
					<td><%= html.html_escape(cert.name.value) %></td>
					<td><%= html.html_escape(cert.subject.value) %></td>
					<td><strong><%= html.html_escape(cert.days_remaining.value) %></strong></td>
					<td><%= html.html_escape(cert.expiration_date.value) %></td>
					<td>
						<span class="label label-<% if cert.color.value == "red" then %>danger<% elseif cert.color.value == "yellow" then %>warning<% else %>success<% end %>">
							<%= html.html_escape(cert.status.value) %>
						</span>
					</td>
					<td>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/viewcert?serial=" .. cert.serial.value) %>"
							class="btn btn-xs btn-info">
							<i class="icon-eye-open"></i> View
						</a>
					</td>
				</tr>
				<% end %>
			</tbody>
		</table>
		<% else %>
		<div class="alert alert-info">
			No certificates found.
		</div>
		<% end %>
	</div>
</div>

<div class="alert alert-info">
	<h4>Status â ACME 1/3-lifetime model</h4>
	<ul>
		<li><span class="label label-success">Valid</span> â More than 1/3 of lifetime remaining</li>
		<li><span class="label label-primary">Soon</span> â Renewal window open (â¤ 33% remaining)</li>
		<li><span class="label label-warning">Warning</span> â Renewal overdue (â¤ 16% remaining)</li>
		<li><span class="label label-danger">Critical</span> â Urgent renewal needed (â¤ 8% remaining)</li>
		<li><span class="label label-danger">Expired</span> â Certificate has expired</li>
	</ul>
	<p class="text-muted" style="margin-top: 8px; margin-bottom: 0;"><small>Thresholds are configurable in PKI Configuration.</small></p>
</div>

<div class="form-group">
</div>
