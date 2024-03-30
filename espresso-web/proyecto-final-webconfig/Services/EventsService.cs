using proyecto_final_webconfig.Models.Entities;
using proyecto_final_webconfig.Repository;

namespace proyecto_final_webconfig.Services
{
    public class EventsService : IEventsService
    {
        private readonly IEventsRepository eventsRepository;
        private readonly IDevicesService devicesService;

        public EventsService(IEventsRepository eventsRepository, IDevicesService devicesService)
        {
            this.eventsRepository = eventsRepository;
            this.devicesService = devicesService;
        }

        public async Task<IEnumerable<Event>> GetAllRecentsEvents()
        {
            return await eventsRepository.GetAllRecentsEvents();
        }
        public async Task<Event> GetEventByID(int id)
        { 
            return await eventsRepository.GetEventByID(id);
        }

        public async Task<IEnumerable<Event>> GetAllRecentsEventsByDevice(string MAC)
        {

            return await eventsRepository.GetAllRecentsEventsByDevice(MAC);

        }


    }
}
