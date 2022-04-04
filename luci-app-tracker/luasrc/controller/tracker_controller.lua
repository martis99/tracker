module("luci.controller.tracker_controller", package.seeall)

function index()
	entry({"admin", "services", "tracker"}, cbi("tracker_model"), "Tracker", 10)
end
